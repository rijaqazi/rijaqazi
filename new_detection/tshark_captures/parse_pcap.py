#!/usr/bin/env python3
"""Compatibility entry point for the backend PCAP parser."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.app.workers.capture.pcap_parser import main


if __name__ == "__main__":
    main()
