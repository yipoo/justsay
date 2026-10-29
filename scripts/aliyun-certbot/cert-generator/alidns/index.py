"""Add and remove only this Certbot order's JustSay TXT value."""
import os
import time

import dns.resolver
from alibabacloud_alidns20150109.client import Client
from alibabacloud_alidns20150109 import models
from alibabacloud_tea_openapi.models import Config

DOMAIN = "justsay.api.53kj.com"
ZONE = "53kj.com"
RR = "_acme-challenge.justsay.api"


def client():
    return Client(Config(
        access_key_id=os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"],
        access_key_secret=os.environ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"],
        security_token=os.environ["ALIBABA_CLOUD_SECURITY_TOKEN"],
        endpoint="alidns.aliyuncs.com", connect_timeout=30000, read_timeout=30000))


def records(api, value):
    out = api.describe_domain_records(models.DescribeDomainRecordsRequest(
        domain_name=ZONE, rrkey_word=RR, type_key_word="TXT", page_size=500)).body
    return [record for record in (out.domain_records.record or [])
            if record.rr == RR and record.type == "TXT" and record.value == value]


def hook(cleanup=False):
    if os.environ.get("CERTBOT_DOMAIN") != DOMAIN:
        raise ValueError("Unexpected Certbot domain")
    value = os.environ["CERTBOT_VALIDATION"]
    api = client()
    matching = records(api, value)
    if cleanup:
        for record in matching:
            api.delete_domain_record(models.DeleteDomainRecordRequest(record_id=record.record_id))
        return
    if not matching:
        api.add_domain_record(models.AddDomainRecordRequest(
            domain_name=ZONE, rr=RR, type="TXT", value=value, ttl=600))
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["223.5.5.5", "119.29.29.29"]
    for _ in range(36):
        try:
            answers = resolver.resolve(f"{RR}.{ZONE}", "TXT", lifetime=5)
            if any(b"".join(answer.strings).decode() == value for answer in answers):
                return
        except dns.exception.DNSException:
            pass
        time.sleep(5)
    raise RuntimeError("JustSay TXT propagation timed out")
