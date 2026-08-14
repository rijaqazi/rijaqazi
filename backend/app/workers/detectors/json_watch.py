"""Run a selected detector for newly parsed packet JSON files."""

import argparse
import subprocess
import sys
import time
from pathlib import Path

from ...core.settings import PROJECT_ROOT, settings


DETECTOR_SCRIPTS = {
    "nmap": PROJECT_ROOT / "nmap" / "nmap_detector.py",
    "arp": PROJECT_ROOT / "arp" / "ARP.py",
    "icmp": PROJECT_ROOT / "icmp" / "icmp.py",
}


def pending_json_files(input_dir, processed):
    directory = Path(input_dir)
    if not directory.is_dir():
        return []
    return sorted(
        path
        for path in directory.glob("*.json")
        if not path.name.endswith("_alerts.json") and path not in processed
    )


def run_detector(detector, json_file, output_dir, runner=subprocess.run):
    script = DETECTOR_SCRIPTS[detector]
    if not script.is_file():
        raise FileNotFoundError(f"Detector script not found: {script}")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(json_file).stem
    return runner(
        [
            sys.executable,
            str(script),
            str(json_file),
            "--log",
            str(output_dir / f"{detector}_alerts.log"),
            "--json-out",
            str(output_dir / f"{stem}_{detector}_alerts.json"),
        ],
        check=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--detector", choices=DETECTOR_SCRIPTS, default="nmap")
    parser.add_argument("--input-dir", default=str(settings.parsed_output_dir))
    parser.add_argument("--output-dir", default=str(settings.detector_output_dir))
    parser.add_argument("--interval", type=int, default=settings.capture_poll_seconds)
    parser.add_argument("--once", action="store_true", help="Process pending JSON files once then exit.")
    args = parser.parse_args()
    if args.interval <= 0:
        raise RuntimeError("--interval must be positive.")
    processed = set()
    while True:
        for json_file in pending_json_files(args.input_dir, processed):
            result = run_detector(args.detector, json_file, args.output_dir)
            if result.returncode == 0:
                processed.add(json_file)
                print(f"[+] Detection completed: {json_file.name}")
            else:
                print(f"[x] Detection failed ({result.returncode}): {json_file.name}")
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
