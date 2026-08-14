"""Tests for ICMP detector rules."""

import unittest

from backend.app.workers.detectors.icmp_detector import detect_icmp_packets


def packet(timestamp):
    return {
        "_source": {
            "layers": {
                "frame": {"frame.time_epoch": str(timestamp)},
                "ip": {"ip.src": "10.0.0.8", "ip.dst": "10.0.0.1"},
                "icmp": {"icmp.type": "8"},
                "eth": {"eth.src": "aa:bb:cc:dd:ee:ff"},
            }
        }
    }


class IcmpDetectorTests(unittest.TestCase):
    def test_detects_echo_flood_at_configured_threshold(self):
        alerts = detect_icmp_packets([packet(1), packet(2)], thresholds={"echo_flood": 2})
        self.assertEqual([alert["alert_type"] for alert in alerts], ["ICMP Echo Request Flood"])
