#!/usr/bin/env python3
"""Compatibility entry point for the endpoint heartbeat agent."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.workers.heartbeat_agent import main


if __name__ == "__main__":
    main()
