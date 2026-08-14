#!/usr/bin/env python3
"""Compatibility entry point for the migrated TAXII push client."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.integrations.taxii.client import push_main


if __name__ == "__main__":
    push_main(sys.argv[1:])
