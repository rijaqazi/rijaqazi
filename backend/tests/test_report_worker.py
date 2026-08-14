"""Tests for report scheduling without PDF or MongoDB dependencies."""

import json
import tempfile
import unittest
from pathlib import Path

from backend.app.workers.report_worker import ReportGenerationWorker


class ReportWorkerTests(unittest.TestCase):
    def test_renders_only_pending_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rules_dir = root / "rules"
            reports_dir = root / "reports"
            rules_dir.mkdir()
            (rules_dir / "rule-one.json").write_text(json.dumps({"rule_id": "rule-one"}), encoding="utf-8")
            (rules_dir / "rule-two.json").write_text(json.dumps({"rule_id": "rule-two"}), encoding="utf-8")
            (reports_dir / "zip").mkdir(parents=True)
            (reports_dir / "zip" / "rule-one.zip").write_bytes(b"done")
            rendered = []

            def renderer(rule_path, _reports_dir, _hours, _token):
                rendered.append(rule_path.stem)
                return {"rule_id": rule_path.stem}

            worker = ReportGenerationWorker(rules_dir, reports_dir, renderer)
            self.assertEqual(worker.load_processed_reports(), 1)
            self.assertEqual(worker.generate_pending_reports(), [{"rule_id": "rule-two"}])
            self.assertEqual(rendered, ["rule-two"])
