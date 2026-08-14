#!/usr/bin/env python3
"""Compatibility entry point for backend IOC extraction."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.services.intelligence.ioc_pipeline import extract_iocs_from_text, update_iocs_from_log
from backend.app.workers.ioc_worker import main, monitor


def monitor_alerts_log():
    """Preserve the original extraction-only monitoring command."""
    monitor("extract")


if __name__ == "__main__":
    main(["--mode", "extract", *sys.argv[1:]])
