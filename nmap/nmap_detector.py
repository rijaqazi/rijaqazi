#!/usr/bin/env python3
"""Canonical Nmap detector command; delegates to the backend entry point."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.workers.detectors.nmap_detector import main


if __name__ == "__main__":
    main()
