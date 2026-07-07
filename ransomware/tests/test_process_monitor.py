"""
Tests for agent/process_monitor/watcher.py
Verifies suspicious process detection and new/exited process tracking.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

AGENT_DIR = os.path.join(os.path.dirname(__file__), "..", "agent")
sys.path.insert(0, AGENT_DIR)


class TestIsSuspicious(unittest.TestCase):
    """Unit tests for suspicious process/command matching."""

    def setUp(self):
        import config
        config.SUSPICIOUS_PROC_NAMES = ["mimikatz", "procdump"]
        config.SUSPICIOUS_CMDLINE_FRAGMENTS = [
            "vssadmin delete shadows",
            "lsass.dmp",
            "-encodedcommand",
        ]

    def _is_suspicious(self, name, cmd):
        from process_monitor.watcher import _is_suspicious
        return _is_suspicious(name, cmd)

    def test_suspicious_name_detected(self):
        self.assertTrue(self._is_suspicious("mimikatz.exe", "mimikatz.exe"))

    def test_suspicious_cmdline_detected(self):
        self.assertTrue(
            self._is_suspicious("powershell.exe",
                                "powershell.exe -encodedcommand AABBC...")
        )

    def test_vssadmin_delete_detected(self):
        self.assertTrue(
            self._is_suspicious("powershell.exe",
                                "vssadmin delete shadows /all /quiet")
        )

    def test_normal_process_not_flagged(self):
        self.assertFalse(self._is_suspicious("notepad.exe", "notepad.exe C:\\Users\\readme.txt"))

    def test_case_insensitive_match(self):
        self.assertTrue(self._is_suspicious("MIMIKATZ.EXE", "MIMIKATZ.EXE"))


class TestProcessMonitorPollOnce(unittest.TestCase):
    """Test that ProcessMonitor emits correct events on new/exited processes."""

    def setUp(self):
        self.patcher = patch("process_monitor.watcher.sender")
        self.mock_sender = self.patcher.start()
        import config
        config.PROCESS_POLL_INTERVAL_SEC = 2
        config.SUSPICIOUS_PROC_NAMES = ["mimikatz"]
        config.SUSPICIOUS_CMDLINE_FRAGMENTS = ["vssadmin delete shadows"]

    def tearDown(self):
        self.patcher.stop()

    @patch("process_monitor.watcher.psutil")
    @patch("process_monitor.watcher._get_proc_info")
    def test_new_process_sends_started_event(self, mock_get_info, mock_psutil):
        from process_monitor.watcher import ProcessMonitor

        # _get_proc_info returns predictable info
        mock_get_info.return_value = {
            "pid": 999,
            "name": "notepad.exe",
            "command": "notepad.exe",
            "exe": "C:\\\\Windows\\\\notepad.exe",
            "ppid": 100,
            "username": "user",
        }
        mock_psutil.NoSuchProcess = OSError
        mock_psutil.AccessDenied = PermissionError
        mock_psutil.Process.return_value = MagicMock()

        monitor = ProcessMonitor()
        monitor._known_pids = {100}  # 999 is new

        mock_psutil.pids.return_value = {100, 999}
        monitor._poll_once()

        self.mock_sender.enqueue.assert_called()
        call_args = self.mock_sender.enqueue.call_args[0]
        self.assertEqual(call_args[0], "process")
        self.assertEqual(call_args[1], "started")

    @patch("process_monitor.watcher.psutil")
    def test_suspicious_process_sends_alert(self, mock_psutil):
        from process_monitor.watcher import ProcessMonitor

        mock_proc = MagicMock()
        mock_proc.pid = 1234
        mock_proc.oneshot.return_value.__enter__ = lambda s: None
        mock_proc.oneshot.return_value.__exit__ = MagicMock(return_value=False)
        mock_proc.name.return_value = "mimikatz.exe"
        mock_proc.cmdline.return_value = ["mimikatz.exe", "privilege::debug"]
        mock_proc.exe.return_value = "C:\\Temp\\mimikatz.exe"
        mock_proc.ppid.return_value = 100
        mock_proc.username.return_value = "user"

        mock_psutil.pids.return_value = {100, 1234}
        mock_psutil.Process.return_value = mock_proc

        monitor = ProcessMonitor()
        monitor._known_pids = {100}  # 1234 is new

        monitor._poll_once()

        call_args = self.mock_sender.enqueue.call_args[0]
        self.assertEqual(call_args[1], "suspicious_start")
        self.assertEqual(call_args[2].get("risk"), "high")


if __name__ == "__main__":
    unittest.main()
