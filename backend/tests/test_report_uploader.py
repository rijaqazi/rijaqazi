"""Tests for safe, upload-only report sharing."""

import tempfile
import unittest
from pathlib import Path

from backend.app.services.reports.report_uploader import sha256_file, upload_new_archives


class FakeResponse:
    status_code = 201

    def __init__(self, payload=None):
        self.payload = payload or {"status": "ok"}

    def json(self):
        return self.payload

    def raise_for_status(self):
        return None


class FakeSession:
    def __init__(self, remote_files=None):
        self.remote_files = remote_files or []
        self.posted = []

    def get(self, _url, **_kwargs):
        return FakeResponse({"status": "ok", "files": self.remote_files})

    def post(self, _url, files, **_kwargs):
        self.posted.append(files["file"][0])
        return FakeResponse()


class ReportUploaderTests(unittest.TestCase):
    def test_skips_matching_hash_and_uploads_new_archive(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            existing = directory / "existing.zip"
            new = directory / "new.zip"
            existing.write_bytes(b"existing archive")
            new.write_bytes(b"new archive")
            session = FakeSession([{"filename": "remote-copy.zip", "sha256": sha256_file(existing)}])

            results = upload_new_archives(session, "http://example.test", ("user", "pass"), [directory])

            self.assertEqual(session.posted, ["new.zip"])
            self.assertEqual([item["status"] for item in results], ["skipped", "ok"])
