import datetime
import json
from pathlib import Path
import sys
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'cert-generator'))
import index as renewal
from alidns import index as dns_hook


def material(domain=renewal.DOMAIN):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), False)
            .sign(key, hashes.SHA256()))
    return cert, cert.public_bytes(serialization.Encoding.PEM).decode(), key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()


class RenewalTests(unittest.TestCase):
    def test_live_valid_certificate_needs_no_cloud_access(self):
        cert, _, _ = material()
        with patch.object(renewal, 'live_certificate', return_value=cert), \
                patch.object(renewal, 'fc') as cloud, patch.object(renewal, 'issue') as issue:
            status = renewal.handler(b'{}', NS(region='cn-beijing'))
            self.assertEqual(status['status'], 'not_due')
            cloud.assert_not_called()
            issue.assert_not_called()

    def test_staging_never_deploys_or_returns_keys(self):
        _, cert, key = material()
        with patch.object(renewal, 'issue', return_value=(cert, key)), \
                patch.object(renewal, 'fc') as cloud:
            status = renewal.handler(b'{"action":"dry_run"}', NS(region='cn-beijing'))
            self.assertEqual(status['status'], 'staging_validated')
            self.assertFalse(status['deployed'])
            cloud.assert_not_called()
            self.assertNotIn('PRIVATE', json.dumps(status))

    def test_renewal_writes_only_target_certificate(self):
        parsed, cert, key = material()
        api = Mock()
        with patch.object(renewal, 'issue', return_value=(cert, key)), \
                patch.object(renewal, 'fc', return_value=api), \
                patch.object(renewal, 'live_certificate', return_value=parsed):
            status = renewal.handler(b'{"action":"force_renew"}', NS(region='cn-beijing'))
        self.assertEqual(status['status'], 'renewed')
        args = api.update_custom_domain.call_args.args
        self.assertEqual(args[0], renewal.DOMAIN)
        self.assertEqual(set(args[1].body.to_map()), {'certConfig'})
        self.assertNotIn('PRIVATE', json.dumps(status))

    def test_mismatched_hostname_is_never_deployed(self):
        _, cert, key = material('other.example.com')
        with patch.object(renewal, 'issue', return_value=(cert, key)), \
                patch.object(renewal, 'fc') as cloud, self.assertRaises(ValueError):
            renewal.handler(b'{"action":"force_renew"}', NS(region='cn-beijing'))
        cloud.assert_not_called()

    def test_reject_other_region_and_hostname(self):
        for evt, region in [(b'{}', 'cn-hangzhou'),
                            (b'{"domainName":"other.example.com"}', 'cn-beijing')]:
            with self.assertRaises(ValueError):
                renewal.handler(evt, NS(region=region))

    def test_dns_cleanup_preserves_other_values_types_and_names(self):
        api = Mock()
        rr = dns_hook.RR
        records = [NS(rr=rr, type='TXT', value='ours', record_id='1'),
                   NS(rr=rr, type='TXT', value='other', record_id='2'),
                   NS(rr=rr, type='CNAME', value='ours', record_id='3'),
                   NS(rr='other', type='TXT', value='ours', record_id='4')]
        api.describe_domain_records.return_value.body.domain_records.record = records
        with patch.dict('os.environ', CERTBOT_DOMAIN=renewal.DOMAIN, CERTBOT_VALIDATION='ours'), \
                patch.object(dns_hook, 'client', return_value=api):
            dns_hook.hook(cleanup=True)
        self.assertEqual(api.delete_domain_record.call_count, 1)
        self.assertEqual(api.delete_domain_record.call_args.args[0].record_id, '1')
        api.update_domain_record.assert_not_called()


if __name__ == '__main__':
    unittest.main()
