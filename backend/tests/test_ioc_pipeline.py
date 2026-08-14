"""Tests for IOC extraction and local STIX generation."""

import json
import tempfile
import unittest
from pathlib import Path

from backend.app.services.intelligence.ioc_pipeline import (
    extract_iocs_from_text,
    generate_stix_bundles,
    read_iocs,
    update_iocs_from_log,
)


class IocPipelineTests(unittest.TestCase):
    def test_extract_rejects_invalid_ipv4_and_deduplicates_values(self):
        iocs = extract_iocs_from_text("192.0.2.8 192.0.2.8 999.1.1.1 AA:BB:CC:DD:EE:FF")
        self.assertEqual(iocs["ip_addresses"], ["192.0.2.8"])
        self.assertEqual(iocs["mac_addresses"], ["aa:bb:cc:dd:ee:ff"])

    def test_updates_iocs_and_generates_one_stix_bundle(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            log_file, ioc_file = root / "alerts.log", root / "iocs.json"
            whitelist_file, bundles = root / "whitelist.json", root / "bundles"
            log_file.write_text("[ALERT] SYN_SCAN from 192.0.2.8 | Ports: 22,80 | Duration: 1\n", encoding="utf-8")
            self.assertTrue(update_iocs_from_log(log_file, ioc_file))
            self.assertEqual(read_iocs(ioc_file)["ip_addresses"], ["192.0.2.8"])
            whitelist_file.write_text(json.dumps({"ip_addresses": [], "mac_addresses": []}), encoding="utf-8")

            created = generate_stix_bundles(log_file, ioc_file, whitelist_file, bundles)
            self.assertEqual(len(created), 1)
            self.assertEqual(generate_stix_bundles(log_file, ioc_file, whitelist_file, bundles), [])
