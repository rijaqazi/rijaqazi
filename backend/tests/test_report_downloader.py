"""Tests for report-download behavior without an HTTP server."""

import tempfile
import unittest
from pathlib import Path

from backend.app.services.reports.report_downloader import download_new_reports


class FakeResponse:
    def __init__(self, payload=None, content=b""):
        self.payload = payload or {}
        self.content = content

    def json(self):
        return self.payload

    def raise_for_status(self):
        return None


class FakeSession:
    def __init__(self):
        self.urls = []

    def get(self, url, **_kwargs):
        self.urls.append(url)
        if url.endswith("/discover"):
            return FakeResponse({"files": [{"filename": "rule-one.zip"}, {"filename": "ignore.txt"}]})
        return FakeResponse(content=b"zip-content")


class ReportDownloaderTests(unittest.TestCase):
    def test_downloads_new_zip_once(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            session = FakeSession()
            downloaded = download_new_reports(session, "http://example.test/", "user", "password", temp_dir)
            self.assertEqual(downloaded, ["rule-one.zip"])
            self.assertEqual((Path(temp_dir) / "rule-one.zip").read_bytes(), b"zip-content")

            downloaded = download_new_reports(session, "http://example.test", "user", "password", temp_dir)
            self.assertEqual(downloaded, [])
