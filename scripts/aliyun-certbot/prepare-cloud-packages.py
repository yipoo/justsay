#!/usr/bin/env python3
"""Prepare maintenance packages in Cloud Shell without exporting credentials."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
ENDPOINT = '1722755712126869.cn-beijing.fc.aliyuncs.com'
os.umask(0o077)


def deployed_code(name):
    result = subprocess.run(['aliyun', 'fc', 'GET', '/2023-03-30/functions/' + name + '/code',
                             '--region', 'cn-beijing', '--version', '2023-03-30',
                             '--endpoint', ENDPOINT], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True, timeout=120)
    if result.returncode:
        raise RuntimeError('Unable to read deployed package: ' + name)
    url = json.loads(result.stdout)['url']
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def main():
    generator = deployed_code('justsay-cert-generator')
    manager = deployed_code('justsay-cert-domain-manager')
    replacements = {str(p.relative_to(ROOT / 'cert-generator')): p.read_bytes()
                    for p in (ROOT / 'cert-generator').rglob('*')
                    if p.is_file() and '__pycache__' not in p.parts}
    retired = {'migration.py', 'cas/index.py', 'scripts/upload-certs.sh'}
    # dnspython is pure Python. The archive is verified against PyPI's digest;
    # its Python 3.10 code runs in FC, not Cloud Shell's older Python interpreter.
    with urllib.request.urlopen('https://pypi.org/pypi/dnspython/2.8.0/json', timeout=30) as response:
        distribution = json.load(response)
    wheel = next(f for f in distribution['urls'] if f['filename'].endswith('py3-none-any.whl'))
    with urllib.request.urlopen(wheel['url'], timeout=60) as response:
        wheel_bytes = response.read()
    if hashlib.sha256(wheel_bytes).hexdigest() != wheel['digests']['sha256']:
        raise RuntimeError('dnspython archive digest mismatch')
    with zipfile.ZipFile(io.BytesIO(generator)) as original, \
            zipfile.ZipFile(ROOT / 'cert-generator.zip', 'w', zipfile.ZIP_DEFLATED) as updated:
        for entry in original.infolist():
            if entry.filename not in replacements and entry.filename not in retired and not entry.filename.startswith('python/dns/'):
                updated.writestr(entry, original.read(entry))
        for name, data in replacements.items():
            item = zipfile.ZipInfo(name)
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = (0o755 if name.endswith('.sh') else 0o644) << 16
            updated.writestr(item, data)
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as dependency:
            for entry in dependency.infolist():
                updated.writestr('python/' + entry.filename, dependency.read(entry))
    node_replacements = {name: (ROOT / 'fc-domain-manager' / name).read_bytes()
                         for name in ('index.js', 'package.json', 'package-lock.json')}
    with zipfile.ZipFile(io.BytesIO(manager)) as original, \
            zipfile.ZipFile(ROOT / 'cert-domain-manager.zip', 'w', zipfile.ZIP_DEFLATED) as updated:
        for entry in original.infolist():
            if entry.filename not in node_replacements:
                updated.writestr(entry, original.read(entry))
        for name, data in node_replacements.items():
            updated.writestr(name, data)
    manifest = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                for name in ('cert-generator.zip', 'cert-domain-manager.zip')}
    (ROOT / 'manifest.json').write_text(json.dumps(manifest))
    print(json.dumps({'stage': 'packages_prepared', 'region': 'cn-beijing', 'sha256': manifest}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'stage': 'prepare_failed', 'error_type': type(error).__name__}), flush=True)
        raise SystemExit(1)
