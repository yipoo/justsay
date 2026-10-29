#!/usr/bin/env python3
"""Run in Alibaba Cloud Shell. Uses its CLI identity; never exports credentials."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

ACCOUNT = '1722755712126869'
REGION = 'cn-beijing'
DOMAIN = 'justsay.api.53kj.com'
ROLE = 'fc-cap-role-73ha'
POLICY = 'JustSayCertificateRenewalBeijing'
ISSUER = 'justsay-cert-generator'
MANAGER = 'justsay-cert-domain-manager'
BROAD = ['AliyunDNSFullAccess', 'AliyunFCFullAccess', 'AliyunYundunCertFullAccess']
ROOT = Path(__file__).resolve().parent
BACKUP = None


def say(stage, **data):
    print(json.dumps(dict(stage=stage, **data)), flush=True)


def cli(args):
    result = subprocess.run(['aliyun'] + args + ['--region', REGION],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=950)
    if result.returncode:
        raise RuntimeError('CLI request failed: ' + ' '.join(args[:2]))
    return json.loads(result.stdout) if result.stdout.strip() else {}


def ram(action, **kwargs):
    args = ['ram', action]
    for key, value in kwargs.items():
        args += ['--' + key, value]
    return cli(args)


def fc(method, path, body=None):
    args = ['fc', method, '/2023-03-30' + path, '--version', '2023-03-30',
            '--endpoint', ACCOUNT + '.' + REGION + '.fc.aliyuncs.com',
            '--read-timeout', '900', '--connect-timeout', '30']
    with tempfile.TemporaryDirectory(prefix='justsay-request-') as folder:
        if body is not None:
            request_file = Path(folder) / 'body.json'
            request_file.write_text(json.dumps(body))
            request_file.chmod(0o600)
            args += ['--body-file', str(request_file), '--header',
                     'Content-Type=application/json;x-fc-invocation-type=Sync;']
        return cli(args)


def policies():
    return {(p['PolicyType'], p['PolicyName']) for p in
            ram('ListPoliciesForRole', RoleName=ROLE)['Policies']['Policy']}


def attach(name, policy_type='System'):
    ram('AttachPolicyToRole', PolicyType=policy_type, PolicyName=name, RoleName=ROLE)


def detach(name, policy_type='System'):
    ram('DetachPolicyFromRole', PolicyType=policy_type, PolicyName=name, RoleName=ROLE)


def deploy(name, package):
    fc('PUT', '/functions/' + name,
       {'code': {'zipFile': base64.b64encode(package.read_bytes()).decode()}})
    for _ in range(60):
        info = fc('GET', '/functions/' + name)
        if info.get('lastUpdateStatus') in (None, 'Successful') and info.get('state') not in ('Pending', 'Failed'):
            say('deployed', function=name, region=REGION)
            return
        time.sleep(2)
    raise RuntimeError('Function deployment did not become ready')


def invoke(name, event):
    result = fc('POST', '/functions/' + name + '/invocations?qualifier=LATEST', event)
    if not isinstance(result, dict) or 'errorMessage' in result:
        # Only known status categories from our function are safe to display.
        category = 'runtime_error'
        if isinstance(result, dict):
            message = result.get('errorMessage', '')
            category = next((c for c in ('AccessDenied', 'NoPermission', 'Forbidden',
                            'ModuleNotFoundError', 'NXDOMAIN', 'Timeout') if c in message), category)
        raise RuntimeError('Invocation failed for ' + name + ': ' + category)
    say('invoked', function=name, result=result)
    return result


def dns_records():
    data = cli(['alidns', 'DescribeDomainRecords', '--DomainName', '53kj.com',
                '--RRKeyWord', '_acme-challenge.justsay.api', '--TypeKeyWord', 'TXT',
                '--PageSize', '500'])
    return {r['RecordId'] for r in data['DomainRecords']['Record']
            if r['RR'] == '_acme-challenge.justsay.api' and r['Type'] == 'TXT'}


def health():
    with socket.create_connection((DOMAIN, 443), timeout=30) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=DOMAIN) as tls:
            cert = tls.getpeercert()
            fingerprint = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
    with urllib.request.urlopen('https://' + DOMAIN + '/health', timeout=30) as response:
        if response.status != 200 or json.load(response).get('ok') is not True:
            raise RuntimeError('Public API health check failed')
    return {'expires': cert['notAfter'], 'sha256': fingerprint, 'health': 'ok'}


def main():
    global BACKUP
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    identity = cli(['sts', 'GetCallerIdentity'])
    if identity.get('AccountId') != ACCOUNT:
        raise RuntimeError('Unexpected Alibaba Cloud account')
    expected_policy = json.loads((ROOT / 'ram-policy.json').read_text())
    version = ram('GetPolicy', PolicyType='Custom', PolicyName=POLICY)['Policy']['DefaultVersion']
    document = ram('GetPolicyVersion', PolicyType='Custom', PolicyName=POLICY,
                   VersionId=version)['PolicyVersion']['PolicyDocument']
    if isinstance(document, str):
        document = json.loads(urllib.parse.unquote(document))
    if document != expected_policy:
        raise RuntimeError('Existing policy differs from reviewed policy')
    original_policies = policies()
    allowed = {('System', p) for p in BROAD} | {('Custom', POLICY)}
    if original_policies - allowed:
        raise RuntimeError('Unexpected additional role policy')
    domain_path = '/custom-domains/' + DOMAIN
    before = fc('GET', domain_path)
    if not any(r.get('functionName') == 'justsay-api' for r in before['routeConfig']['routes']):
        raise RuntimeError('Unexpected application route')
    trigger = fc('GET', '/functions/' + MANAGER + '/triggers/time-trigger')
    config = json.loads(trigger['triggerConfig'])
    if not config.get('enable'):
        raise RuntimeError('Daily Beijing timer is not enabled')
    baseline = health()
    say('preflight', account=ACCOUNT, region=REGION, policy=POLICY,
        policies=sorted(original_policies), timer=config, live=baseline)
    if not args.apply:
        return
    BACKUP = Path(tempfile.mkdtemp(prefix='justsay-rollback-'))
    (BACKUP / 'domain.json').write_text(json.dumps(before))
    (BACKUP / 'policies.json').write_text(json.dumps(sorted(original_policies)))
    packages = {ISSUER: ROOT / 'cert-generator.zip', MANAGER: ROOT / 'cert-domain-manager.zip'}
    manifest = json.loads((ROOT / 'manifest.json').read_text())
    for name, package in packages.items():
        if hashlib.sha256(package.read_bytes()).hexdigest() != manifest[package.name]:
            raise RuntimeError('Uploaded package hash mismatch')
        info = fc('GET', '/functions/' + name)
        if info['role'] != 'acs:ram::' + ACCOUNT + ':role/' + ROLE:
            raise RuntimeError('Unexpected execution role')
        url = fc('GET', '/functions/' + name + '/code')['url']
        with urllib.request.urlopen(url, timeout=120) as response:
            (BACKUP / (name + '.zip')).write_bytes(response.read())
    initial_records = dns_records()
    try:
        attach(POLICY, 'Custom')
        for name in BROAD:
            if ('System', name) in policies():
                detach(name)
        if policies() != {('Custom', POLICY)}:
            raise RuntimeError('Unexpected policies remain attached')
        say('role_restricted', policy=POLICY, removed=BROAD)
        # New code creates fresh runtimes after the role policies were changed.
        for name, package in packages.items():
            deploy(name, package)
        for _ in range(12):
            isolation = invoke(ISSUER, {'action': 'verify_isolation'})
            if isolation.get('status') == 'isolation_verified':
                break
            time.sleep(10)
        else:
            raise RuntimeError('Runtime permissions are still broader than expected')
        if invoke(ISSUER, {'action': 'dry_run'}).get('status') != 'staging_validated':
            raise RuntimeError('Staging validation failed')
        if dns_records() != initial_records:
            raise RuntimeError('DNS staging validation records were not cleaned up')
        if invoke(ISSUER, {'action': 'force_renew'}).get('status') != 'renewed':
            raise RuntimeError('Production renewal failed')
        if invoke(MANAGER, {}).get('status') != 'not_due':
            raise RuntimeError('Daily manager check failed')
        after = fc('GET', domain_path)
        for field in ('routeConfig', 'protocol', 'authConfig', 'tlsConfig', 'wafConfig'):
            if before.get(field) != after.get(field):
                raise RuntimeError('Domain setting changed outside certificate configuration')
        live = health()
        if live['sha256'] == baseline['sha256'] or dns_records() != initial_records:
            raise RuntimeError('Renewal or DNS cleanup was not confirmed')
        if policies() != {('Custom', POLICY)}:
            raise RuntimeError('Role policy verification failed')
        say('complete', domain=DOMAIN, region=REGION, policy=POLICY, live=live,
            timer_enabled=True, backup=str(BACKUP))
    except BaseException:
        say('rollback_started')
        for name in BROAD:
            if ('System', name) in original_policies:
                attach(name)
        for name in packages:
            deploy(name, BACKUP / (name + '.zip'))
        if ('Custom', POLICY) not in original_policies:
            detach(POLICY, 'Custom')
        # Remove only new challenge records created by this cutover test.
        for record_id in dns_records() - initial_records:
            cli(['alidns', 'DeleteDomainRecord', '--RecordId', record_id])
        say('rollback_complete', region=REGION, policies=sorted(policies()), live=health())
        raise


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        # API payloads and credential values are never printed.
        say('failed', error_type=type(error).__name__,
            reason=str(error) if isinstance(error, RuntimeError) else 'See private diagnostics')
        sys.exit(1)
