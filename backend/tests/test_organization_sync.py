"""Database-free tests for organization intelligence matching."""

import unittest

from backend.app.services.intelligence.organization_sync import build_sync_plan, extract_target_ip_from_raw_alert


class OrganizationSyncTests(unittest.TestCase):
    def test_matches_active_targets_and_related_iocs(self):
        plan = build_sync_plan(
            ["10.0.0.10"],
            [{"_id": "alert-1", "target_ip": "10.0.0.10"}],
            [{"_id": "cvss-1", "source_ip": "198.51.100.9", "raw_alert": "Target_IP: 10.0.0.10"}],
            [{"_id": "ioc-target", "ip_address": "10.0.0.10"}, {"_id": "ioc-source", "ip_address": "198.51.100.9"}],
        )
        self.assertEqual([item["_id"] for item in plan["alerts"]], ["alert-1"])
        self.assertEqual([item["_id"] for item in plan["cvss"]], ["cvss-1"])
        self.assertEqual({item["_id"] for item in plan["iocs"]}, {"ioc-target", "ioc-source"})

    def test_extracts_target_ip_from_raw_alert(self):
        self.assertEqual(extract_target_ip_from_raw_alert("x | Target_IP: 192.0.2.1 | y"), "192.0.2.1")
