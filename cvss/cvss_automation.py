#!/usr/bin/env python3
"""Compatibility entry point for the migrated CVSS worker."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.services.scoring.cvss_service import calculate_cvss_score, get_priority, process_alert
from backend.app.workers.cvss_worker import run_cvss_automation


if __name__ == "__main__":
    try:
        run_cvss_automation()
    except KeyboardInterrupt:
        print("[+] CVSS automation stopped.")
