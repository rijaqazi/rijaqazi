"""Tests for detection of pending PCAP files."""

import tempfile
import unittest
from pathlib import Path

from backend.app.workers.capture.pcap_watch import parse_pending, pending_pcaps


class PcapWatchTests(unittest.TestCase):
    def test_finds_and_marks_only_unparsed_pcaps(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            captures, parsed = root / "captures", root / "parsed"
            captures.mkdir()
            parsed.mkdir()
            (captures / "done.pcap").write_bytes(b"pcap")
            (captures / "new.pcapng").write_bytes(b"pcapng")
            (parsed / "done_parsed.json").write_text("[]", encoding="utf-8")
            self.assertEqual([path.name for path in pending_pcaps(captures, parsed)], ["new.pcapng"])

            def fake_parser(source, output_dir, _tshark):
                output = Path(output_dir) / f"{Path(source).stem}_parsed.json"
                output.write_text("[]", encoding="utf-8")
                return output

            results = parse_pending(captures, parsed, parser=fake_parser)
            self.assertEqual([path.name for path in results], ["new_parsed.json"])
