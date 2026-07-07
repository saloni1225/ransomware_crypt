"""
Tests for AgentSender (agent/sender.py)
Uses unittest.mock to avoid real HTTP calls.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Ensure agent directory is on path
AGENT_DIR = os.path.join(os.path.dirname(__file__), "..", "agent")
sys.path.insert(0, AGENT_DIR)


class TestAgentSender(unittest.TestCase):
    """Unit tests for AgentSender event queuing and batch logic."""

    def setUp(self):
        # Create a temporary DB file for isolation
        self.db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.db_file.name
        self.db_file.close()

    def tearDown(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass

    @patch("sender.requests.Session")
    def test_enqueue_adds_to_queue(self, mock_session_cls):
        mock_session_cls.return_value = MagicMock()
        from sender import AgentSender
        from offline_db import OfflineDB

        s = AgentSender()
        s._db = OfflineDB(self.db_path)

        s.enqueue("file", "modified", {"path": "/tmp/test.txt"})
        self.assertEqual(s._db.get_count(), 1)
        batch = s._db.get_batch(1)
        self.assertEqual(len(batch), 1)
        event = batch[0]["event"]
        self.assertEqual(event["type"], "file")
        self.assertEqual(event["action"], "modified")

    @patch("sender.requests.Session")
    def test_batch_flush_clears_queue(self, mock_session_cls):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_session = MagicMock()
        mock_session.post.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        from sender import AgentSender
        from offline_db import OfflineDB

        s = AgentSender()
        s._db = OfflineDB(self.db_path)

        for i in range(5):
            s.enqueue("file", "created", {"path": f"/tmp/file{i}.txt"})

        self.assertEqual(s._db.get_count(), 5)

        # Retrieve and post batch like the sync loop does
        batch_items = s._db.get_batch(5)
        batch_events = [item["event"] for item in batch_items]
        batch_ids = [item["id"] for item in batch_items]

        success = s._post_batch(batch_events)
        self.assertTrue(success)
        s._db.delete_batch(batch_ids)

        self.assertEqual(s._db.get_count(), 0)

    @patch("sender.requests.Session")
    def test_failed_post_goes_to_retry_queue(self, mock_session_cls):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        mock_session = MagicMock()
        mock_session.post.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        from sender import AgentSender
        from offline_db import OfflineDB

        s = AgentSender()
        s._db = OfflineDB(self.db_path)

        s.enqueue("usb", "mounted", {"label": "BadDrive", "authorized": False})
        
        batch_items = s._db.get_batch(1)
        batch_events = [item["event"] for item in batch_items]
        
        success = s._post_batch(batch_events)
        self.assertFalse(success)
        # Event should remain in offline db for retry on subsequent loops
        self.assertEqual(s._db.get_count(), 1)


class TestBatchEndpointFallback(unittest.TestCase):
    """Test that sender falls back to individual POSTs when batch endpoint fails."""

    @patch("sender.requests.Session")
    def test_fallback_to_individual_posts(self, mock_session_cls):
        mock_session = MagicMock()

        batch_resp = MagicMock()
        batch_resp.status_code = 404  # batch endpoint not found

        individual_resp = MagicMock()
        individual_resp.status_code = 201

        # First call (batch) fails, subsequent calls (individual) succeed
        mock_session.post.side_effect = [batch_resp, individual_resp, individual_resp]
        mock_session_cls.return_value = mock_session

        from sender import AgentSender
        
        s = AgentSender()
        result = s._post_batch([
            {"device_id": "h", "type": "file", "action": "created", "details": {}},
            {"device_id": "h", "type": "file", "action": "deleted", "details": {}},
        ])
        self.assertTrue(result)
        # Should have called post 3 times: 1 batch + 2 individual
        self.assertEqual(mock_session.post.call_count, 3)


if __name__ == "__main__":
    unittest.main()
