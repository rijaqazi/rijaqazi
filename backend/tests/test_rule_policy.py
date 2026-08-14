"""Database-free tests for rule-generation policy."""

import unittest
from datetime import datetime

from backend.app.services.rules.rule_policy import build_rule, decide_action, find_cvss_entry, infer_protocol


class FakeCVSSCollection:
    def __init__(self):
        self.entries = [
            {"source_ip": "10.0.0.8", "attack_type": "SYN_SCAN", "cvss_score": 8.5, "priority": "high"}
        ]

    def find_one(self, query):
        return next(
            (
                entry
                for entry in self.entries
                if entry["source_ip"] == query["source_ip"] and entry["attack_type"] == query["attack_type"]
            ),
            None,
        )

    def find(self, query):
        return [entry for entry in self.entries if entry["source_ip"] == query["source_ip"]]


class RulePolicyTests(unittest.TestCase):
    def setUp(self):
        self.alert = {"_id": "alert-1", "alert_type": "SYN_SCAN", "src_ip": "10.0.0.8", "duration_sec": 4}

    def test_syn_scan_is_blocked_and_inferred_as_tcp(self):
        decision = decide_action(self.alert)
        self.assertEqual(decision["action"], "block_ip")
        self.assertEqual(infer_protocol(self.alert), "TCP")

    def test_cvss_lookup_accepts_space_underscore_variants(self):
        entry = find_cvss_entry(FakeCVSSCollection(), "10.0.0.8", "SYN SCAN")
        self.assertEqual(entry["priority"], "high")

    def test_rule_json_has_stable_fields(self):
        rule = build_rule(
            self.alert,
            {"cvss_score": 8.5, "priority": "high"},
            decide_action(self.alert),
            "rule-test",
            datetime(2026, 1, 2, 3, 4, 5),
        )
        self.assertEqual(rule["rule_id"], "rule-test")
        self.assertEqual(rule["created"], "2026-01-02T03:04:05Z")
        self.assertEqual(rule["protocol"], "TCP")
