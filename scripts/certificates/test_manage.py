import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("manage", Path(__file__).with_name("manage.py"))
manage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manage)


class CertificateAutomationTests(unittest.TestCase):
    def test_target_is_independent_of_memoryai(self):
        self.assertEqual(manage.DOMAIN, "justsay.api.53kj.com")
        self.assertEqual(manage.REGION, "cn-beijing")
        self.assertEqual(manage.RR, "_acme-challenge.justsay.api")

    def domain(self, function="justsay-api", protocol="HTTP,HTTPS"):
        return SimpleNamespace(protocol=protocol, route_config=SimpleNamespace(
            to_map=lambda: {"routes": [{"functionName": function, "path": "/*"}]}))

    def test_preflight_accepts_existing_http_and_https(self):
        client = Mock()
        client.get_custom_domain.return_value.body = self.domain()
        with patch.object(manage, "fc", return_value=client), patch.dict(
            os.environ, {"DNS_AUTOMATION_ENABLED": "false"}
        ):
            manage.preflight()
        client.get_custom_domain.assert_called_once_with(manage.DOMAIN)

    def test_preflight_rejects_wrong_function(self):
        client = Mock()
        client.get_custom_domain.return_value.body = self.domain(function="memoryai-api")
        with patch.object(manage, "fc", return_value=client):
            with self.assertRaisesRegex(RuntimeError, "route target"):
                manage.preflight()

    def test_preflight_rejects_http_only(self):
        client = Mock()
        client.get_custom_domain.return_value.body = self.domain(protocol="HTTP")
        with patch.object(manage, "fc", return_value=client):
            with self.assertRaisesRegex(RuntimeError, "protocol"):
                manage.preflight()

    def test_dns_rejects_other_domain_before_cloud_access(self):
        with patch.dict(os.environ, {"CERTBOT_DOMAIN": "api.53kj.com"}), patch.object(
            manage, "dns_client"
        ) as client:
            with self.assertRaisesRegex(RuntimeError, "Unexpected domain"):
                manage.dns_hook()
        client.assert_not_called()

    def test_cleanup_deletes_only_current_order_value(self):
        rows = [
            SimpleNamespace(rr=manage.RR, type="TXT", value="current", record_id="ours"),
            SimpleNamespace(rr=manage.RR, type="TXT", value="other-order", record_id="other"),
            SimpleNamespace(rr="_acme-challenge.api", type="TXT", value="current", record_id="memory"),
        ]
        client = Mock()
        with patch.dict(os.environ, {"CERTBOT_DOMAIN": manage.DOMAIN,
                                    "CERTBOT_VALIDATION": "current"}), patch.object(
            manage, "records", return_value=rows
        ), patch.object(manage, "dns_client", return_value=client):
            manage.dns_hook(True)
        self.assertEqual(client.delete_domain_record.call_count, 1)
        self.assertEqual(client.delete_domain_record.call_args.args[0].record_id, "ours")

    def test_dns_auth_is_idempotent(self):
        row = SimpleNamespace(rr=manage.RR, type="TXT", value="current")
        client = Mock()
        with patch.dict(os.environ, {"CERTBOT_DOMAIN": manage.DOMAIN,
                                    "CERTBOT_VALIDATION": "current"}), patch.object(
            manage, "records", return_value=[row]
        ), patch.object(manage, "dns_client", return_value=client), patch.object(
            manage, "wait_for_dns"
        ) as propagated:
            manage.dns_hook()
        client.add_domain_record.assert_not_called()
        propagated.assert_called_once_with("current")

    def test_state_is_encrypted_and_requires_independent_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / "source"
            (state / "config").mkdir(parents=True)
            (state / "config" / "private.txt").write_text("secret-test-material")
            encrypted = root / "state.enc"
            with patch.object(manage, "STATE", state), patch.dict(os.environ, {
                "ACME_STATE_ENCRYPTION_KEY": "unit-test-key",
                "STATE_ARCHIVE": str(encrypted),
            }):
                manage.crypt_state(True)
            self.assertNotIn(b"secret-test-material", encrypted.read_bytes())
            restored = root / "restore"
            with patch.object(manage, "STATE", restored), patch.dict(os.environ, {
                "ACME_STATE_ENCRYPTION_KEY": "unit-test-key",
                "STATE_ARCHIVE": str(encrypted),
            }):
                manage.crypt_state(False)
            self.assertEqual((restored / "config/private.txt").read_text(), "secret-test-material")


if __name__ == "__main__":
    unittest.main()
