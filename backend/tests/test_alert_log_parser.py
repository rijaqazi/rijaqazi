"""Tests for normalized detector-log parsing."""

import unittest

from backend.app.services.alerts.alert_log_parser import parse_alert_line


class AlertLogParserTests(unittest.TestCase):
    def test_parses_detector_alert_fields(self):
        alert = parse_alert_line(
            "2026-08-14 12:00:00 - ARP_FLOOD ALERT from 10.0.0.8 | Target_IP: 10.0.0.1 | "
            "SRC_MAC: aa:bb:cc:dd:ee:ff | Claimed_MAC: N/A | Previous_MAC: N/A | "
            "Ports: 80, 443 | Ports Scanned: 2 | Start: 2026-08-14 11:59:58 | Duration: 2.0s"
        )
        self.assertEqual(alert["alert_type"], "ARP_FLOOD")
        self.assertEqual(alert["ports"], ["80", "443"])
        self.assertEqual(alert["duration_sec"], 2.0)

    def test_ignores_non_alert_lines(self):
        self.assertIsNone(parse_alert_line("normal startup message"))
