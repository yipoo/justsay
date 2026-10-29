"""Issue and deploy only justsay.api.53kj.com's TLS certificate; never change routes."""
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tarfile
import time

from alibabacloud_tea_openapi.models import Config
from alibabacloud_fc20230330.client import Client as FC
from alibabacloud_fc20230330 import models as fc_models
from alibabacloud_alidns20150109.client import Client as DNS
from alibabacloud_alidns20150109 import models as dns_models
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import base64

DOMAIN = "justsay.api.53kj.com"
ZONE = "53kj.com"
RR = "_acme-challenge.justsay.api"
REGION = "cn-beijing"
STATE = Path(os.environ.get("CERT_STATE", "/tmp/justsay-cert-state"))


def config(endpoint):
    return Config(access_key_id=os.environ["ALIYUN_ACCESS_KEY_ID"],
                  access_key_secret=os.environ["ALIYUN_ACCESS_KEY_SECRET"],
                  endpoint=endpoint, region_id=REGION)


def fc():
    return FC(config("fcv3.cn-beijing.aliyuncs.com"))


def dns_client():
    return DNS(config("alidns.aliyuncs.com"))


def records():
    result = dns_client().describe_domain_records(dns_models.DescribeDomainRecordsRequest(
        domain_name=ZONE, rrkey_word=RR, type_key_word="TXT", page_size=100))
    return result.body.domain_records.record or []


def preflight():
    domain = fc().get_custom_domain(DOMAIN).body
    routes = domain.route_config.to_map()
    print(json.dumps({"domain": DOMAIN, "region": REGION,
                      "protocol": domain.protocol, "routes": routes}))
    if "HTTPS" not in (domain.protocol or "").upper().split(","):
        raise RuntimeError("Unexpected protocol; refusing to alter configuration")
    if not any(r.get("functionName") == "justsay-api"
               for r in routes.get("routes", [])):
        raise RuntimeError("Unexpected route target")
    if os.environ.get("DNS_AUTOMATION_ENABLED") == "true":
        records()
        print("FC custom-domain read and DNS read permissions verified")
    else:
        print("FC target verified; DNS renewal is disabled pending permission approval")


def dns_hook(cleanup=False):
    if os.environ["CERTBOT_DOMAIN"] != DOMAIN:
        raise RuntimeError("Unexpected domain")
    value = os.environ["CERTBOT_VALIDATION"]
    matching = [r for r in records() if r.rr == RR and r.type == "TXT" and r.value == value]
    if cleanup:
        for record in matching:
            dns_client().delete_domain_record(dns_models.DeleteDomainRecordRequest(record_id=record.record_id))
        print("Removed this order's DNS validation record")
        return
    if not matching:
        dns_client().add_domain_record(dns_models.AddDomainRecordRequest(
            domain_name=ZONE, rr=RR, type="TXT", value=value, ttl=600))
    wait_for_dns(value)


def wait_for_dns(value, attempts=30):
    import dns.resolver
    resolver = dns.resolver.Resolver()
    # Check public propagation before asking the CA to validate it.
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    for attempt in range(attempts):
        try:
            answers = resolver.resolve(f"{RR}.{ZONE}", "TXT", lifetime=10)
            if any(b"".join(a.strings).decode() == value for a in answers):
                print("DNS validation record propagated")
                return
        except Exception:
            pass
        time.sleep(10)
    raise RuntimeError("DNS TXT propagation timed out")


def deploy():
    client = fc()
    before = client.get_custom_domain(DOMAIN).body
    cert_dir = STATE / "config" / "live" / DOMAIN
    chain = (cert_dir / "fullchain.pem").read_text()
    # FC expects the RSA PKCS#1 PEM form, while Certbot writes PKCS#8.
    private_key = serialization.load_pem_private_key(
        (cert_dir / "privkey.pem").read_bytes(), password=None
    ).private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()).decode()
    certificate = x509.load_pem_x509_certificate(chain.encode())
    if DOMAIN not in certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName):
        raise RuntimeError("Certificate hostname mismatch")
    if before.cert_config and before.cert_config.certificate and before.cert_config.certificate.strip() == chain.strip():
        print("Current FC certificate already matches; no cloud update needed")
        return
    body = fc_models.UpdateCustomDomainInput().from_map({
        "certConfig": {"certName": "letsencrypt-justsay-api-53kj-com", "certificate": chain, "privateKey": private_key}
    })
    client.update_custom_domain(DOMAIN, fc_models.UpdateCustomDomainRequest(body=body))
    after = client.get_custom_domain(DOMAIN).body
    for field in ("route_config", "protocol", "auth_config", "tls_config", "waf_config"):
        left, right = getattr(before, field, None), getattr(after, field, None)
        left = left.to_map() if hasattr(left, "to_map") else left
        right = right.to_map() if hasattr(right, "to_map") else right
        if left != right:
            raise RuntimeError(f"Unexpected change to {field}; inspect deployment immediately")
    print("Updated TLS certificate; routes, protocol, authentication and TLS settings preserved")


def verify():
    import urllib.request
    for attempt in range(24):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((DOMAIN, 443), timeout=15) as sock:
                with context.wrap_socket(sock, server_hostname=DOMAIN) as tls:
                    cert = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
            remaining = (cert.not_valid_after_utc.timestamp() - time.time()) / 86400
            if remaining < 30:
                raise RuntimeError("Live certificate expires in less than 30 days")
            with urllib.request.urlopen(f"https://{DOMAIN}/health", timeout=30) as response:
                data = json.load(response)
                if data.get("ok") is not True:
                    raise RuntimeError("Health check failed")
            print(json.dumps({"domain": DOMAIN, "issuer": cert.issuer.rfc4514_string(),
                              "expires": cert.not_valid_after_utc.isoformat(),
                              "remaining_days": round(remaining, 1), "health": "healthy"}))
            return
        except Exception:
            if attempt == 23:
                raise
            time.sleep(10)


def crypt_state(encrypt):
    # Only encrypted ACME account/certificate state leaves the ephemeral runner.
    secret = os.environ["ACME_STATE_ENCRYPTION_KEY"]
    key = base64.urlsafe_b64encode(hashlib.sha256(("justsay-acme-state-v1:" + secret).encode()).digest())
    cipher = Fernet(key)
    target = Path(os.environ["STATE_ARCHIVE"])
    if encrypt:
        if not (STATE / "config").exists():
            return
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            archive.add(STATE / "config", arcname="config")
        target.write_bytes(cipher.encrypt(stream.getvalue()))
        print("Encrypted ACME state for the next renewal")
    else:
        if not target.exists():
            print("No prior ACME state; first issuance")
            return
        STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(cipher.decrypt(target.read_bytes())), mode="r:gz") as archive:
            archive.extractall(STATE, filter="data")
        print("Restored encrypted ACME state")


if __name__ == "__main__":
    commands = {"preflight": preflight, "dns-auth": dns_hook,
                "dns-cleanup": lambda: dns_hook(True), "deploy": deploy,
                "verify": verify, "encrypt": lambda: crypt_state(True),
                "decrypt": lambda: crypt_state(False)}
    commands[sys.argv[1]]()
