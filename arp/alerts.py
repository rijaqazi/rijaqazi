#!/usr/bin/env python3
"""Compatibility entry point for importing ARP detector alerts."""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.workers.alert_log_ingestion import main


if __name__ == "__main__":
    main(Path(__file__).with_name("alerts_arp.log"), "myDatabase", "Alerts2")
