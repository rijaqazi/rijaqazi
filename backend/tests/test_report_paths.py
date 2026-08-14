"""Tests for report output path selection."""

import unittest
from pathlib import Path

from backend.app.services.reports.report_paths import RULES_DIR, report_output_paths


class ReportPathTests(unittest.TestCase):
    def test_default_paths_are_project_relative(self):
        root, reports_dir, zip_dir = report_output_paths()
        self.assertTrue(root.is_absolute())
        self.assertEqual(reports_dir, root / "REPORT")
        self.assertEqual(zip_dir, root / "zip")
        self.assertTrue(RULES_DIR.is_absolute())

    def test_custom_output_path_is_respected(self):
        root, reports_dir, zip_dir = report_output_paths(Path("custom-reports"))
        self.assertEqual(root, Path("custom-reports"))
        self.assertEqual(reports_dir, Path("custom-reports/REPORT"))
        self.assertEqual(zip_dir, Path("custom-reports/zip"))
