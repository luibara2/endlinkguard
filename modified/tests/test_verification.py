import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


module_path = (
    Path(__file__).parents[1]
    / "src"
    / "endlinkguard"
    / "verification.py"
)
spec = importlib.util.spec_from_file_location("backend_verification", module_path)
assert spec is not None and spec.loader is not None
verification = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verification
spec.loader.exec_module(verification)

VerificationError = verification.VerificationError
canonical_payload = verification.canonical_payload
sign_request = verification.sign_request
verify_pending_join = verification.verify_pending_join


class FakeResponse:
    status = 200

    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self):
        return json.dumps(self.payload).encode()


class VerificationProtocolTest(unittest.TestCase):
    def setUp(self):
        self.request = {
            "xuid": "",
            "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "name": "Player One",
            "address": "127.0.0.1",
            "timestamp": "1786014098445",
            "nonce": "abc123",
        }

    def test_canonical_payload_matches_java_verifier_order(self):
        self.assertEqual(
            canonical_payload(self.request),
            "v1\n\naaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n"
            "Player One\n127.0.0.1\n1786014098445\nabc123",
        )

    def test_signature_is_hmac_sha256_hex(self):
        self.assertEqual(
            sign_request("test-secret", self.request),
            "13e3f8f873defc7d1865714bd6101c1b7290a5b429b9e504a0c78cdaea895005",
        )

    def test_verification_error_is_runtime_error(self):
        self.assertTrue(issubclass(VerificationError, RuntimeError))

    def test_verified_identity_comes_from_proxy_response(self):
        response = FakeResponse(
            {
                "name": "Player One",
                "xuid": "2535459084817261",
                "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "backend": "skygen",
                "real_ip": "2001:db8::42",
                "real_port": 42123,
            }
        )
        with patch.object(verification.urllib.request, "urlopen", return_value=response):
            identity = verify_pending_join(
                "http://127.0.0.1:19135/verify",
                "test-secret",
                name="player one",
                address="127.0.0.1",
            )

        self.assertEqual(identity.xuid, "2535459084817261")
        self.assertEqual(identity.unique_id, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
        self.assertEqual(identity.backend, "skygen")
        self.assertEqual(identity.real_ip, "2001:db8::42")
        self.assertEqual(identity.real_port, 42123)

    def test_rejects_invalid_real_client_ip(self):
        response = FakeResponse(
            {
                "name": "Player One",
                "xuid": "2535459084817261",
                "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "real_ip": "not-an-ip",
                "real_port": 42123,
            }
        )
        with patch.object(verification.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(VerificationError, "invalid real client IP"):
                verify_pending_join(
                    "http://127.0.0.1:19135/verify",
                    "test-secret",
                    name="Player One",
                    address="127.0.0.1",
                )

    def test_rejects_non_ascii_xuid(self):
        response = FakeResponse(
            {
                "name": "Player One",
                "xuid": "١٢٣",
                "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            }
        )
        with patch.object(verification.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(VerificationError, "invalid XUID"):
                verify_pending_join(
                    "http://127.0.0.1:19135/verify",
                    "test-secret",
                    name="Player One",
                    address="127.0.0.1",
                )


if __name__ == "__main__":
    unittest.main()
