#!/usr/bin/env python3
"""Compatibility entry point for organization intelligence synchronization."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.workers.organization_sync_worker import main


if __name__ == "__main__":
    main()
