"""Tests for the backend-owned secure upload service."""

import base64
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from backend.app.services.rules.upload_service import create_app, make_hash, save_credentials


def basic_auth(username: str, password: str):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


class UploadServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.upload_dir = root / "uploads"
        self.creds_file = root / "creds.json"
        salt = b"test-salt-123456"
        save_credentials(self.creds_file, "tester", salt.hex(), make_hash("safe-password", salt))
        self.client = create_app(self.upload_dir, self.creds_file).test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_health_is_public_and_discovery_requires_authentication(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        self.assertEqual(self.client.get("/discover").status_code, 401)

    def test_valid_zip_is_uploaded_and_listed(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zip_file:
            zip_file.writestr("rule.txt", "alert test")
        archive.seek(0)

        response = self.client.post(
            "/upload",
            data={"file": (archive, "rule.zip")},
            headers=basic_auth("tester", "safe-password"),
        )
        self.assertEqual(response.status_code, 201)

        response = self.client.get("/discover", headers=basic_auth("tester", "safe-password"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["files"][0]["filename"], "rule.zip")
