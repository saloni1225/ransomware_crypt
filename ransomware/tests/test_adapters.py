"""
Tests for SentinelCrypt Adapter Framework
=========================================
Tests capability checks, payload normalization, secret redaction,
registry resolution, and live collection across all 7 security modules.
"""
import json
import os
import sys
import unittest

# Ensure agent and backend directories are on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT_DIR = os.path.join(BASE_DIR, "agent")
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
sys.path.insert(0, AGENT_DIR)
sys.path.insert(0, BACKEND_DIR)

from adapters.base import AdapterCapability, CapabilityState, NormalizedPayload, BaseAdapter, UnsupportedAdapter
from adapters.registry import register, get_adapter, available_modules
from adapters.common.normalizer import redact_sensitive, sanitize_payload, serialize, to_sender_event


class DummyAdapter(BaseAdapter):
    MODULE = "dummy"

    def check_capability(self) -> AdapterCapability:
        return AdapterCapability(
            module=self.MODULE,
            supported=True,
            capability_state=CapabilityState.SUPPORTED,
            message="Dummy supported",
        )

    def _collect(self) -> dict:
        return {"foo": "bar", "secret": "AKIA1234567890ABCDEF"}

    def _compute_health(self, data: dict) -> str:
        return "healthy"


class TestAdapterBase(unittest.TestCase):
    """Test BaseAdapter contract and NormalizedPayload serialization."""

    def test_capability_serialization(self):
        cap = AdapterCapability(
            module="test",
            supported=True,
            capability_state=CapabilityState.SUPPORTED,
            message="OK",
        )
        d = cap.to_dict()
        self.assertEqual(d["module"], "test")
        self.assertTrue(d["supported"])
        self.assertEqual(d["capability_state"], "supported")

    def test_collect_returns_normalized_payload(self):
        adapter = DummyAdapter()
        payload = adapter.collect()
        self.assertIsInstance(payload, NormalizedPayload)
        self.assertEqual(payload.module, "dummy")
        self.assertTrue(payload.supported)
        self.assertEqual(payload.health, "healthy")
        self.assertEqual(payload.data["foo"], "bar")
        self.assertIn("collected_at", payload.to_dict())

    def test_unsupported_adapter(self):
        adapter = UnsupportedAdapter("unknown_mod")
        payload = adapter.collect()
        self.assertFalse(payload.supported)
        self.assertEqual(payload.health, "unknown")
        self.assertEqual(payload.capability.capability_state, "unsupported_os")


class TestAdapterRegistry(unittest.TestCase):
    """Test runtime adapter selection and registration."""

    def test_registry_registration(self):
        register("dummy", "Windows", DummyAdapter)
        register("dummy", "Linux", DummyAdapter)
        register("dummy", "Darwin", DummyAdapter)
        self.assertIn("dummy", available_modules())

        adapter = get_adapter("dummy")
        self.assertIsInstance(adapter, DummyAdapter)

    def test_registry_fallback_for_unknown_module(self):
        adapter = get_adapter("nonexistent_module_xyz")
        self.assertIsInstance(adapter, UnsupportedAdapter)
        self.assertEqual(adapter.MODULE, "nonexistent_module_xyz")


class TestNormalizer(unittest.TestCase):
    """Test payload sanitization and secret redaction."""

    def test_redact_sensitive_aws_key(self):
        text = "My AWS key is AKIAIOSFODNN7EXAMPLE and secret is safe."
        redacted = redact_sensitive(text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_redact_sensitive_stripe_key(self):
        text = "Stripe sk_dummy_1234567890abcdef1234567890 active."
        redacted = redact_sensitive(text)
        self.assertNotIn("sk_dummy_1234567890abcdef1234567890", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_sanitize_payload_recursive(self):
        payload = {
            "module": "test",
            "nested": {
                "key1": "AKIA1111222233334444",
                "key2": "normal_val",
                "list_val": ["sk_dummy_abcdefghijklmnopqrstuvwx", "safe_string"],
            },
        }
        cleaned = sanitize_payload(payload)
        self.assertEqual(cleaned["nested"]["key1"], "[REDACTED]")
        self.assertEqual(cleaned["nested"]["key2"], "normal_val")
        self.assertEqual(cleaned["nested"]["list_val"][0], "[REDACTED]")
        self.assertEqual(cleaned["nested"]["list_val"][1], "safe_string")

    def test_serialize(self):
        payload = {"key": "AKIA1111222233334444"}
        json_str = serialize(payload)
        self.assertNotIn("AKIA", json_str)
        self.assertIn("[REDACTED]", json_str)

    def test_to_sender_event(self):
        adapter = DummyAdapter()
        payload = adapter.collect()
        log_type, action, details = to_sender_event(payload)
        self.assertEqual(log_type, "dummy")
        self.assertEqual(action, "telemetry_snapshot")
        self.assertEqual(details["data"]["secret"], "[REDACTED]")


class TestModuleAdapters(unittest.TestCase):
    """Test calling collect() on all 7 real security module adapters."""

    def test_all_modules_return_normalized_payload(self):
        modules = ["malware", "network", "firewall", "browser", "privacy", "deception", "wifi"]
        for mod in modules:
            with self.subTest(module=mod):
                adapter = get_adapter(mod)
                payload = adapter.collect()
                self.assertIsInstance(payload, NormalizedPayload)
                self.assertEqual(payload.module, mod)
                self.assertIsInstance(payload.supported, bool)
                self.assertIn(payload.health, ["healthy", "warning", "critical", "unknown", "degraded"])
                # Verify JSON serializability
                d = payload.to_dict()
                json_str = json.dumps(d, default=str)
                self.assertIsInstance(json_str, str)


class TestBackendCapabilitiesEndpoint(unittest.TestCase):
    """Test Phase 4 backend capabilities aggregation endpoints."""

    def setUp(self):
        from fastapi.testclient import TestClient
        from app.main import app
        from app.services.auth_service import get_current_user
        app.dependency_overrides[get_current_user] = lambda: {"email": "admin@defense.com", "role": "admin"}
        self.client = TestClient(app)
        self.app = app

    def tearDown(self):
        self.app.dependency_overrides.clear()

    def test_list_all_capabilities(self):
        r = self.client.get("/api/capabilities/")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIsInstance(data, list)

    def test_get_device_capabilities(self):
        r = self.client.get("/api/capabilities/test-device-id-123")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["device_id"], "test-device-id-123")
        self.assertIn("capabilities", data)
        self.assertIn("malware", data["capabilities"])
        self.assertIn("firewall", data["capabilities"])
        self.assertIn("browser", data["capabilities"])
        self.assertIn("privacy", data["capabilities"])


if __name__ == "__main__":
    unittest.main()

