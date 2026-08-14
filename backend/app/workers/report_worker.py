"""Schedule report rendering for generated rule JSON files."""

import json
import time
from pathlib import Path


class ReportGenerationWorker:
    """Track completed reports and call an injected PDF/ZIP renderer for pending rules."""

    def __init__(self, rules_dir, reports_dir, renderer):
        self.rules_dir = Path(rules_dir)
        self.reports_dir = Path(reports_dir)
        self.renderer = renderer
        self.processed_rule_ids = set()

    def load_processed_reports(self):
        self.processed_rule_ids.clear()
        for directory, suffix in ((self.reports_dir / "zip", ".zip"), (self.reports_dir / "REPORT", "-report.pdf")):
            if not directory.is_dir():
                continue
            for path in directory.iterdir():
                if path.is_file() and path.name.endswith(suffix):
                    self.processed_rule_ids.add(path.name[: -len(suffix)])
        return len(self.processed_rule_ids)

    @staticmethod
    def _rule_id(rule_path):
        try:
            return json.loads(rule_path.read_text(encoding="utf-8")).get("rule_id") or rule_path.stem
        except (OSError, json.JSONDecodeError):
            return rule_path.stem

    def generate_pending_reports(self, hours=24, ipinfo_token=None):
        if not self.rules_dir.is_dir():
            return []
        reports = []
        for rule_path in sorted(self.rules_dir.glob("*.json")):
            rule_id = self._rule_id(rule_path)
            if rule_id in self.processed_rule_ids:
                continue
            result = self.renderer(rule_path, self.reports_dir, hours, ipinfo_token)
            if result:
                self.processed_rule_ids.add(result.get("rule_id", rule_id))
                reports.append(result)
        return reports

    def monitor(self, hours=24, ipinfo_token=None, interval=30):
        if interval <= 0:
            raise ValueError("interval must be positive")
        print(f"[!] Loaded {self.load_processed_reports()} previously processed rules")
        while True:
            reports = self.generate_pending_reports(hours, ipinfo_token)
            print(f"Generated {len(reports)} report(s).")
            time.sleep(interval)
