"""One-time, fixed-target move from the template's Hangzhou defaults to Beijing."""
import base64
import io
import json
import logging
import os
from pathlib import Path
import tempfile
import time

import requests
from alibabacloud_tea_openapi.models import Config
from alibabacloud_fc20230330.client import Client
from alibabacloud_fc20230330 import models
from alibabacloud_cas20200407 import models as cas_models
from cas.index import client as cas_client, runtime

DOMAIN = "justsay.api.53kj.com"
ISSUER = "justsay-cert-generator"
MANAGER = "justsay-cert-domain-manager"
CERT_NAME = "devs-certbot-generated-justsay-beijing"
MARKER = "JustSay certificate automation; managed from yipoo/justsay"


def quiet_logs():
    logging.getLogger().setLevel(logging.WARNING)
    for logger in list(logging.Logger.manager.loggerDict.values()):
        if isinstance(logger, logging.Logger):
            logger.setLevel(logging.WARNING)


def fc(region):
    return Client(Config(
        access_key_id=os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"],
        access_key_secret=os.environ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"],
        security_token=os.environ["ALIBABA_CLOUD_SECURITY_TOKEN"],
        endpoint=f"1722755712126869.{region}.fc.aliyuncs.com", region_id=region,
        read_timeout=900000, connect_timeout=30000))


def copy_function(source, target, name):
    original = source.get_function(name, models.GetFunctionRequest()).body
    try:
        existing = target.get_function(name, models.GetFunctionRequest()).body
    except Exception as error:
        if getattr(error, "code", None) not in ("FunctionNotFound", "ResourceNotFound"):
            raise
    else:
        if existing.description != MARKER:
            raise RuntimeError("Refusing to overwrite an existing unmanaged function")
        print(f"Beijing function already created: {name}")
        return
    location = source.get_function_code(name, models.GetFunctionCodeRequest()).body
    response = requests.get(location.url, timeout=120)
    response.raise_for_status()
    code = models.InputCodeLocation(zip_file=base64.b64encode(response.content).decode())
    env = dict(original.environment_variables or {})
    if name == MANAGER:
        env["CUSTOM_DOMAIN_REGIONS"] = "cn-beijing"
    body = models.CreateFunctionInput(
        function_name=name, runtime=original.runtime, handler=original.handler,
        role=original.role, timeout=original.timeout, cpu=original.cpu,
        memory_size=original.memory_size, disk_size=original.disk_size,
        instance_concurrency=1, internet_access=True,
        environment_variables=env, code=code, description=MARKER)
    target.create_function(models.CreateFunctionRequest(body=body))
    for _ in range(60):
        status = target.get_function(name, models.GetFunctionRequest()).body
        if status.last_update_status in (None, "Successful") and status.state not in ("Pending", "Failed"):
            print(f"Created Beijing function: {name}")
            return
        time.sleep(2)
    raise RuntimeError("Beijing function did not become ready")


def invoke(client, name, event):
    response = client.invoke_function_with_options(name, models.InvokeFunctionRequest(
        body=io.BytesIO(json.dumps(event).encode())),
        models.InvokeFunctionHeaders(x_fc_invocation_type="Sync"), runtime)
    data = response.body.read() if hasattr(response.body, "read") else response.body
    if isinstance(data, bytes):
        data = data.decode()
    if response.headers.get("x-fc-error-type"):
        raise RuntimeError(f"Function invocation failed: {name}")
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return data


def retire_test_certificate():
    # This test certificate was never attached to the live domain. Its private
    # key appeared in upstream SDK debug output; revoke it after suppressing logs.
    detail = cas_client.get_user_certificate_detail_with_options(
        cas_models.GetUserCertificateDetailRequest(cert_id=28151143), runtime).body
    if detail.common != DOMAIN:
        raise RuntimeError("Unexpected test certificate hostname")
    import certbot.main
    with tempfile.TemporaryDirectory(prefix="justsay-retire-") as folder:
        root = Path(folder)
        cert, key = root / "cert.pem", root / "key.pem"
        cert.write_text(detail.cert)
        key.write_text(detail.key)
        key.chmod(0o600)
        try:
            certbot.main.main([
                "revoke", "--cert-path", str(cert), "--key-path", str(key),
                "--reason", "keycompromise", "--no-delete-after-revoke",
                "--quiet", "--non-interactive", "--server",
                "https://acme-v02.api.letsencrypt.org/directory"])
        except Exception as error:
            if "already revoked" not in str(error).lower():
                raise RuntimeError("Failed to revoke unused test certificate") from None
        finally:
            quiet_logs()
    print("Unused test certificate revoked")


def run(context):
    if context.region != "cn-hangzhou":
        raise RuntimeError("One-time migration must run from the original template region")
    quiet_logs()
    source, target = fc("cn-hangzhou"), fc("cn-beijing")
    for name in (ISSUER, MANAGER):
        copy_function(source, target, name)
    cert_id = int(invoke(target, ISSUER, {"domainName": DOMAIN, "certName": CERT_NAME}))
    print(f"Beijing issuer returned certificate ID: {cert_id}")
    cert = cas_client.get_user_certificate_detail_with_options(
        cas_models.GetUserCertificateDetailRequest(cert_id=cert_id), runtime).body
    if cert.common != DOMAIN or cert_id == 28151143:
        raise RuntimeError("Unexpected new certificate")
    before = target.get_custom_domain(DOMAIN).body
    if not any(r.function_name == "justsay-api" for r in before.route_config.routes):
        raise RuntimeError("Unexpected live function route")
    target.update_custom_domain(DOMAIN, models.UpdateCustomDomainRequest(
        body=models.UpdateCustomDomainInput(cert_config=models.CertConfig(
            cert_name=CERT_NAME, certificate=cert.cert, private_key=cert.key))))
    after = target.get_custom_domain(DOMAIN).body
    for field in ("route_config", "protocol", "auth_config", "tls_config", "waf_config"):
        left, right = getattr(before, field, None), getattr(after, field, None)
        left = left.to_map() if hasattr(left, "to_map") else left
        right = right.to_map() if hasattr(right, "to_map") else right
        if left != right:
            raise RuntimeError("Unexpected domain setting change")
    print("Beijing custom domain bound; routes and authentication preserved")
    if invoke(target, MANAGER, {}) != "done":
        raise RuntimeError("Rotation check failed")
    print("Beijing rotation manager check succeeded")
    config = json.dumps({"payload": "", "cronExpression":
                         "CRON_TZ=Asia/Shanghai 0 0 0 * * *", "enable": True})
    try:
        trigger = target.get_trigger(MANAGER, "time-trigger").body
    except Exception as error:
        if getattr(error, "code", None) not in ("TriggerNotFound", "ResourceNotFound"):
            raise
        target.create_trigger(MANAGER, models.CreateTriggerRequest(
            body=models.CreateTriggerInput(trigger_name="time-trigger", trigger_type="timer",
                                           qualifier="LATEST", trigger_config=config)))
    else:
        if trigger.trigger_type != "timer":
            raise RuntimeError("Unexpected existing trigger")
        target.update_trigger(MANAGER, "time-trigger", models.UpdateTriggerRequest(
            body=models.UpdateTriggerInput(trigger_config=config, qualifier="LATEST")))
    print("Beijing daily timer enabled at 00:00 Singapore")
    retire_test_certificate()
    for region in ("cn-hangzhou", "ap-southeast-1"):
        old = fc(region)
        trigger = old.get_trigger(MANAGER, "time-trigger").body
        old_config = json.loads(trigger.trigger_config)
        old_config["enable"] = False
        old.update_trigger(MANAGER, "time-trigger", models.UpdateTriggerRequest(
            body=models.UpdateTriggerInput(trigger_config=json.dumps(old_config))))
        for name in (MANAGER, ISSUER):
            old.update_function(name, models.UpdateFunctionRequest(
                body=models.UpdateFunctionInput(disable_ondemand=True)))
        print(f"Disabled old renewal functions and timer in {region}")
    return {"region": "cn-beijing", "domain": DOMAIN, "certificate_id": cert_id,
            "issuer": ISSUER, "manager": MANAGER, "timer_enabled": True}
