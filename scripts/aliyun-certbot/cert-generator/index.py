"""Renew one Beijing FC domain without access to the account's certificate store."""
import datetime
import json
import logging
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from alibabacloud_fc20230330.client import Client
from alibabacloud_fc20230330 import models
from alibabacloud_tea_openapi.models import Config

DOMAIN = "justsay.api.53kj.com"
REGION = "cn-beijing"
ACCOUNT = "1722755712126869"
CERT_NAME = "devs-certbot-generated-justsay-beijing"
PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


def quiet_logs():
    logging.getLogger().setLevel(logging.WARNING)
    for logger in list(logging.Logger.manager.loggerDict.values()):
        if isinstance(logger, logging.Logger):
            logger.setLevel(logging.WARNING)


def live_certificate():
    with socket.create_connection((DOMAIN, 443), timeout=20) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=DOMAIN) as tls:
            return x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))


def fc():
    return Client(Config(
        access_key_id=os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"],
        access_key_secret=os.environ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"],
        security_token=os.environ["ALIBABA_CLOUD_SECURITY_TOKEN"],
        endpoint=f"{ACCOUNT}.{REGION}.fc.aliyuncs.com", region_id=REGION,
        connect_timeout=30000, read_timeout=60000))


def validate_material(chain, key):
    cert = x509.load_pem_x509_certificate(chain.encode())
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if names.get_values_for_type(x509.DNSName) != [DOMAIN]:
        raise ValueError("Unexpected certificate names")
    private_key = serialization.load_pem_private_key(key.encode(), password=None)
    if private_key.public_key().public_numbers() != cert.public_key().public_numbers():
        raise ValueError("Certificate and key do not match")
    if cert.not_valid_after_utc <= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("Certificate has expired")
    pkcs1 = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    return cert, pkcs1


def issue(root, staging):
    env = dict(os.environ, DEVS_DOMAIN=DOMAIN)
    args = [sys.executable, "-c", "import sys, certbot.main; sys.exit(certbot.main.main())",
            "certonly", "--manual",
            "--preferred-challenges", "dns", "--manual-auth-hook",
            "/code/scripts/authenticator.sh", "--manual-cleanup-hook",
            "/code/scripts/cleanup.sh", "--config-dir", str(root / "config"),
            "--work-dir", str(root / "work"), "--logs-dir", str(root / "logs"),
            "--cert-name", DOMAIN, "--domains", DOMAIN, "--key-type", "rsa",
            "--rsa-key-size", "2048", "--non-interactive", "--agree-tos",
            "--register-unsafely-without-email", "--quiet", "--server",
            STAGING if staging else PRODUCTION]
    # Separate process prevents Certbot from enabling SDK upload debug logs.
    result = subprocess.run(args, env=env, capture_output=True, timeout=700)
    if result.returncode:
        stderr = result.stderr.decode(errors="replace")
        category = next((code for code in ("AccessDenied", "NoPermission", "Forbidden",
                        "ModuleNotFoundError", "NXDOMAIN", "Timeout") if code in stderr), "unknown")
        raise RuntimeError(f"Certbot DNS validation failed: {category} (exit {result.returncode})")
    folder = root / "config" / "live" / DOMAIN
    return (folder / "fullchain.pem").read_text(), (folder / "privkey.pem").read_text()


def handler(event, context):
    quiet_logs()
    if context.region != REGION:
        raise ValueError("Renewal must run in cn-beijing")
    evt = json.loads(event or b"{}")
    if evt.get("domainName", DOMAIN) != DOMAIN:
        raise ValueError("Unexpected domain")
    action = evt.get("action", "check")
    if action not in ("check", "dry_run", "force_renew", "verify_isolation"):
        raise ValueError("Unsupported action")
    if action == "verify_isolation":
        try:
            fc().list_functions(models.ListFunctionsRequest(limit=1))
        except Exception as error:
            code = getattr(error, "code", "")
            if "AccessDenied" not in code and "Forbidden" not in code:
                raise RuntimeError("Unable to verify runtime permission isolation") from None
            return {"domain": DOMAIN, "region": REGION, "status": "isolation_verified",
                    "denied_action": "fc:ListFunctions"}
        return {"domain": DOMAIN, "region": REGION, "status": "permissions_not_restricted"}
    if action == "check":
        try:
            current = live_certificate()
        except ssl.SSLCertVerificationError as error:
            if error.verify_code != 10:
                raise RuntimeError("Live TLS verification failed") from None
        else:
            remaining = current.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)
            if remaining.total_seconds() >= 7 * 86400:
                return {"domain": DOMAIN, "region": REGION, "status": "not_due",
                        "expires": current.not_valid_after_utc.isoformat()}
    with tempfile.TemporaryDirectory(prefix="justsay-acme-") as folder:
        chain, key = issue(Path(folder), action == "dry_run")
        cert, pkcs1 = validate_material(chain, key)
        if action == "dry_run":
            return {"domain": DOMAIN, "region": REGION, "status": "staging_validated",
                    "deployed": False}
        quiet_logs()
        try:
            fc().update_custom_domain(DOMAIN, models.UpdateCustomDomainRequest(
                body=models.UpdateCustomDomainInput(cert_config=models.CertConfig(
                    cert_name=CERT_NAME, certificate=chain, private_key=pkcs1))))
        except Exception:
            raise RuntimeError("Updating the Beijing domain certificate failed") from None
        for _ in range(24):
            if live_certificate().serial_number == cert.serial_number:
                return {"domain": DOMAIN, "region": REGION, "status": "renewed",
                        "expires": cert.not_valid_after_utc.isoformat()}
            time.sleep(5)
        raise RuntimeError("Live certificate did not update before verification timed out")
