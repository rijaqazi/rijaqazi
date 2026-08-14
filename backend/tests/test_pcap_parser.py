"""Tests for PCAP parsing command construction and output handling."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from backend.app.workers.capture.pcap_parser import parse_pcap


class PcapParserTests(unittest.TestCase):
    def test_writes_tshark_json_to_requested_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "capture.pcap"
            source.write_bytes(b"pcap")
            commands = []

            def runner(command, **_kwargs):
                commands.append(command)
                return SimpleNamespace(stdout="[{}]")

            output = parse_pcap(source, root / "parsed", runner=runner)
            self.assertEqual(output.read_text(encoding="utf-8"), "[{}]")
            self.assertEqual(commands, [["tshark", "-r", str(source), "-T", "json"]])
