"""Tests for protocol-aware live capture monitoring helpers."""

import unittest
from pathlib import Path

from backend.app.workers.capture.protocol_monitor import ProtocolMonitor, capture_command, safe_bpf


class ProtocolMonitorTests(unittest.TestCase):
    def test_detects_syn_scan_after_unique_ports_threshold(self):
        monitor = ProtocolMonitor(thresholds={"syn": 2})
        self.assertIsNone(monitor.process_line("10|192.0.2.8||aa:bb:cc:dd:ee:ff|0x02|22||||"))
        alert = monitor.process_line("11|192.0.2.8||aa:bb:cc:dd:ee:ff|0x02|80||||")
        self.assertEqual(alert["reason"], "SYN_SCAN (2 ports)")

    def test_capture_command_rejects_unsafe_packet_source(self):
        with self.assertRaises(ValueError):
            capture_command("eth0", "host 1.2.3.4", Path("capture.pcap"), 10)

    def test_capture_command_uses_argument_list(self):
        command = capture_command("eth0", "192.0.2.8", Path("capture.pcap"), 10)
        self.assertEqual(command[:4], ["tshark", "-i", "eth0", "-f"])
        self.assertEqual(safe_bpf("192.0.2.8"), "host 192.0.2.8")

