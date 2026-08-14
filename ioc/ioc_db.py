#!/usr/bin/env python3
"""Compatibility entry point for the migrated STIX ingestion worker."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.services.intelligence.stix_ingestion import create_service, main, monitor


def push_stix_bundles_to_mongodb():
    """Preserve the legacy one-time ingestion function."""
    service = create_service()
    service.load_processed_bundles()
    return service.ingest_once()


def monitor_and_push():
    """Preserve the legacy continuous monitoring function."""
    monitor()


if __name__ == "__main__":
    main()
