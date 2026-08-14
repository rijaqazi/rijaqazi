"""Database-free tests for STIX ingestion behavior."""

import json
import tempfile
import unittest
from pathlib import Path

from backend.app.services.intelligence.stix_ingestion import StixIngestionService


class FakeIOCRepository:
    def __init__(self):
        self.bundles = set()
        self.records = []

    def existing_bundle_ids(self):
        return self.bundles.copy()

    def bundle_exists(self, bundle_id):
        return bundle_id in self.bundles

    def insert_bundle_objects(self, bundle_id, objects):
        self.bundles.add(bundle_id)
        self.records.extend({"bundle_id": bundle_id, **obj} for obj in objects)
        return len(objects)


class StixIngestionTests(unittest.TestCase):
    def test_ingests_a_valid_bundle_once(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            bundles_dir = Path(temporary_directory)
            bundle = {
                "type": "bundle",
                "id": "bundle--example",
                "objects": [{"type": "indicator", "id": "indicator--example"}],
            }
            (bundles_dir / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
            repository = FakeIOCRepository()
            service = StixIngestionService(repository, bundles_dir)

            self.assertEqual(service.ingest_once(), (1, 1, 0))
            self.assertEqual(service.ingest_once(), (0, 0, 1))
            self.assertEqual(len(repository.records), 1)


if __name__ == "__main__":
    unittest.main()
