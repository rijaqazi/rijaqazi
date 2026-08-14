"""Tests for ARP detection rules."""

import unittest

from backend.app.workers.detectors.arp_detector import detect_arp_packets


def packet(source_ip, source_mac, target_ip, epoch):
    return {
        "_source": {
            "layers": {
                "eth": {"eth.src": source_mac},
                "arp": {"arp.src.proto_ipv4": source_ip, "arp.dst.proto_ipv4": target_ip, "arp.dst.hw_mac": "aa:bb:cc:dd:ee:ff"},
                "frame": {"frame.time_epoch": str(epoch)},
            }
        }
    }


class ArpDetectorTests(unittest.TestCase):
    def test_detects_ip_to_mac_change_as_arp_spoofing(self):
        alerts = detect_arp_packets(
            [packet("10.0.0.9", "00:11:22:33:44:55", "10.0.0.1", 1), packet("10.0.0.9", "66:77:88:99:aa:bb", "10.0.0.1", 2)]
        )
        self.assertIn("ARP_SPOOF", [alert["alert_type"] for alert in alerts])
