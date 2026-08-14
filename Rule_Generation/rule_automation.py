#!/usr/bin/env python3
"""Compatibility entry point for the migrated rule-generation worker."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.workers.rule_worker import main


if __name__ == "__main__":
    main()
