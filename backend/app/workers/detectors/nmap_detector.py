"""Canonical entry point for the existing Nmap detector during migration."""

import subprocess
import sys
from pathlib import Path

from ...core.settings import PROJECT_ROOT


LEGACY_DETECTOR = PROJECT_ROOT / "nmap" / "final.py"


def run_detector(arguments, runner=subprocess.run):
    """Run the established detector without shell command construction."""
    if not LEGACY_DETECTOR.is_file():
        raise FileNotFoundError(f"Nmap detector not found: {LEGACY_DETECTOR}")
    return runner([sys.executable, str(LEGACY_DETECTOR), *arguments], check=False)


def main():
    result = run_detector(sys.argv[1:])
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
