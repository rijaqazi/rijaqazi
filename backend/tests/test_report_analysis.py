"""Tests for report risk and enrichment calculations."""

import unittest

from backend.app.services.reports.report_analysis import compute_risk, normalize_ipinfo, risk_category


class ReportAnalysisTests(unittest.TestCase):
    def test_risk_score_and_category(self):
        score = compute_risk(9, 8, reputation_score=0.5, asset_criticality=0.5)
        self.assertEqual(score, 79.0)
        self.assertEqual(risk_category(score), "High")

    def test_private_ip_enrichment_is_normalized_without_mutation(self):
        payload = {"bogon": True, "ip": "10.0.0.1"}
        normalized = normalize_ipinfo(payload)
        self.assertEqual(normalized["country"], "Private Network")
        self.assertNotIn("raw", payload)
        self.assertEqual(normalized["raw"], payload)
