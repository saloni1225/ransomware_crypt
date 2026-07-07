"""
Tests for agent/file_monitor/watcher.py
Verifies entropy calculation, rapid-mod detection, and event handler routing.
"""

import math
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

AGENT_DIR = os.path.join(os.path.dirname(__file__), "..", "agent")
sys.path.insert(0, AGENT_DIR)


class TestShannonEntropy(unittest.TestCase):
    """Verify entropy helper correctly classifies data."""

    def _entropy(self, data: bytes) -> float:
        from file_monitor.watcher import _shannon_entropy
        return _shannon_entropy(data)

    def test_zero_entropy_uniform(self):
        data = bytes([0x41] * 1000)  # all 'A'
        self.assertAlmostEqual(self._entropy(data), 0.0)

    def test_high_entropy_random(self):
        import random
        random.seed(42)
        data = bytes([random.randint(0, 255) for _ in range(4096)])
        entropy = self._entropy(data)
        self.assertGreater(entropy, 7.0)

    def test_medium_entropy_text(self):
        text = ("The quick brown fox jumps over the lazy dog. " * 50).encode()
        entropy = self._entropy(text)
        self.assertGreater(entropy, 3.0)
        self.assertLess(entropy, 7.0)

    def test_empty_data(self):
        self.assertEqual(self._entropy(b""), 0.0)


class TestRapidModTracker(unittest.TestCase):
    def setUp(self):
        from file_monitor.watcher import RapidModTracker
        # threshold=5 in a 2-second window for fast testing
        self.tracker = RapidModTracker(threshold=5, window_sec=2)

    def test_no_alert_below_threshold(self):
        for _ in range(4):
            result = self.tracker.record()
        self.assertFalse(result)

    def test_alert_at_threshold(self):
        results = [self.tracker.record() for _ in range(5)]
        self.assertTrue(results[-1])

    def test_alert_suppressed_after_first(self):
        for _ in range(5):
            self.tracker.record()
        # Alert was raised. Next call should NOT raise again.
        result = self.tracker.record()
        self.assertFalse(result)

    def test_window_expiry(self):
        for _ in range(5):
            self.tracker.record()
        # Wait for window to expire
        time.sleep(2.1)
        # Tracker resets — single event should not alert
        result = self.tracker.record()
        self.assertFalse(result)


class TestSecurityEventHandler(unittest.TestCase):
    """Tests that the watchdog handler routes events correctly."""

    def setUp(self):
        # Patch sender so no real HTTP calls are made
        self.patcher = patch("file_monitor.watcher.sender")
        self.mock_sender = self.patcher.start()
        import config
        config.DECOY_FILES = ["salary.xlsx", "passwords.txt"]
        config.ENTROPY_THRESHOLD = 7.2
        config.RAPID_MOD_THRESHOLD = 5
        config.RAPID_MOD_WINDOW_SEC = 10

    def tearDown(self):
        self.patcher.stop()

    def _make_handler(self):
        from file_monitor.watcher import SecurityEventHandler
        return SecurityEventHandler()

    def _fake_event(self, path: str, is_directory: bool = False):
        evt = MagicMock()
        evt.src_path = path
        evt.is_directory = is_directory
        return evt

    def test_directory_events_ignored(self):
        handler = self._make_handler()
        evt = self._fake_event("C:/Users/test/Documents", is_directory=True)
        handler.on_created(evt)
        handler.on_deleted(evt)
        handler.on_modified(evt)
        self.mock_sender.enqueue.assert_not_called()

    def test_normal_file_created_sends_event(self):
        handler = self._make_handler()
        evt = self._fake_event("C:/Users/test/Documents/report.docx")
        handler.on_created(evt)
        self.mock_sender.enqueue.assert_called_once()
        args = self.mock_sender.enqueue.call_args[0]
        self.assertEqual(args[0], "file")
        self.assertEqual(args[1], "created")

    def test_decoy_file_access_sends_decoy_event(self):
        handler = self._make_handler()
        evt = self._fake_event("C:/Users/test/Documents/salary.xlsx")
        with patch("file_monitor.watcher._file_entropy", return_value=4.0):
            handler.on_modified(evt)
        call_args = self.mock_sender.enqueue.call_args
        details = call_args[0][2]
        self.assertTrue(details.get("decoy"))

    def test_high_entropy_modification_sets_risk(self):
        handler = self._make_handler()
        evt = self._fake_event("C:/Users/test/Documents/invoice.pdf")
        with patch("file_monitor.watcher._file_entropy", return_value=7.9):
            handler.on_modified(evt)
        call_args = self.mock_sender.enqueue.call_args
        details = call_args[0][2]
        self.assertEqual(details.get("risk"), "high")

    def test_suspicious_extension_sets_risk(self):
        handler = self._make_handler()
        evt = self._fake_event("C:/Users/test/Documents/report.docx.locked")
        with patch("file_monitor.watcher._file_entropy", return_value=3.0):
            handler.on_modified(evt)
        call_args = self.mock_sender.enqueue.call_args
        details = call_args[0][2]
        self.assertTrue(details.get("risk") == "high" or details.get("extension_alert"))

    def test_rename_sends_renamed_event(self):
        handler = self._make_handler()
        evt = MagicMock()
        evt.src_path = "C:/Users/test/file.doc"
        evt.dest_path = "C:/Users/test/file.doc.locked"
        evt.is_directory = False
        handler.on_moved(evt)
        args = self.mock_sender.enqueue.call_args[0]
        self.assertEqual(args[1], "renamed")


class TestBatchEndpoint(unittest.TestCase):
    """Integration-style test for POST /api/threats/logs/batch."""

    def setUp(self):
        os.environ["TESTING"] = "True"
        from fastapi.testclient import TestClient
        from app.main import app
        self.client = TestClient(app)

    def tearDown(self):
        os.environ.pop("TESTING", None)

    def _get_token(self):
        """Register + login to get a token for auth-required endpoints."""
        self.client.post("/api/auth/register", json={
            "email": "batchtest@test.com",
            "password": "TestPass123!"
        })
        return None  # batch endpoint is open (no auth needed)

    def test_batch_endpoint_accepts_events(self):
        payload = {
            "events": [
                {
                    "device_id": "test-host",
                    "type": "file",
                    "action": "created",
                    "details": {"path": "/tmp/a.txt"}
                },
                {
                    "device_id": "test-host",
                    "type": "file",
                    "action": "deleted",
                    "details": {"path": "/tmp/b.txt"}
                },
            ]
        }
        resp = self.client.post("/api/threats/logs/batch", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("accepted", data)
        self.assertEqual(data["accepted"], 2)
        self.assertEqual(data["rejected"], 0)


if __name__ == "__main__":
    unittest.main()
