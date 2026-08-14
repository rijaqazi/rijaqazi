#!/usr/bin/env python3
"""Compatibility entry point for the project service launcher."""

import os
import sys
from pathlib import Path


if __name__ == "__main__":
    launcher = Path(__file__).resolve().parents[1] / "scripts" / "launcher.py"
    os.execv(sys.executable, [sys.executable, str(launcher), *sys.argv[1:]])
