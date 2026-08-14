"""Database-free tests for the rule-generation worker."""

import json
import tempfile
import unittest
from pathlib import Path

from backend.app.workers.rule_worker import RuleGenerationWorker


class FakeRuleRepository:
    def alerts(self):
        return [
            {"_id": "one", "alert_type": "SYN_SCAN", "src_ip": "10.0.0.8", "duration_sec": 2},
            {"_id": "two", "alert_type": "ICMP", "src_ip": "10.0.0.9", "duration_sec": None},
        ]

    def cvss_for_alert(self, source_ip, _alert_type):
        return {"cvss_score": 8.5, "priority": "high"} if source_ip == "10.0.0.8" else None


class RuleWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.rules_dir = Path(self.temp_dir.name) / "rules"
        self.worker = RuleGenerationWorker(FakeRuleRepository(), self.rules_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generates_rule_and_skips_invalid_duration(self):
        summary = self.worker.process_new_alerts()
        self.assertEqual(summary["new_rules"], 1)
        self.assertEqual(summary["skipped_duration_na"], 1)
        rule = json.loads(next(self.rules_dir.glob("*.json")).read_text(encoding="utf-8"))
        self.assertEqual(rule["decision"]["action"], "block_ip")

    def test_processed_rule_files_are_not_generated_again(self):
        self.worker.process_new_alerts()
        self.worker.load_processed_alerts()
        summary = self.worker.process_new_alerts()
        self.assertEqual(summary["skipped_processed"], 1)
