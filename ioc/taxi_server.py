#!/usr/bin/env python3
"""Compatibility entry point for the migrated TAXII service."""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.integrations.taxii.server import app, main


if __name__ == "__main__":
    main()
