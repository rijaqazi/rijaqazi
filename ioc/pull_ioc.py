#!/usr/bin/env python3
"""Compatibility entry point for the migrated TAXII pull client."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.integrations.taxii.client import pull_main


if __name__ == "__main__":
    # Preserve the legacy ``monitor`` argument while supporting ``--monitor``.
    arguments = ["--monitor" if value == "monitor" else value for value in sys.argv[1:]]
    pull_main(arguments)
