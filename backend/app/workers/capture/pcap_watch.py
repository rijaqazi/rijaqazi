"""Watch a capture directory and parse new PCAP files with tshark."""

import argparse
import time
from pathlib import Path

from ...core.settings import settings
from .pcap_parser import parse_pcap


PCAP_SUFFIXES = {".pcap", ".pcapng"}


def pending_pcaps(capture_dir, parsed_dir):
    capture_dir, parsed_dir = Path(capture_dir), Path(parsed_dir)
    if not capture_dir.is_dir():
        return []
    completed = {path.name.removesuffix("_parsed.json") for path in parsed_dir.glob("*_parsed.json")} if parsed_dir.is_dir() else set()
    return sorted(path for path in capture_dir.iterdir() if path.is_file() and path.suffix.lower() in PCAP_SUFFIXES and path.stem not in completed)


def parse_pending(capture_dir, parsed_dir, tshark_executable="tshark", parser=parse_pcap):
    parsed = []
    for pcap_file in pending_pcaps(capture_dir, parsed_dir):
        parsed.append(parser(pcap_file, parsed_dir, tshark_executable))
    return parsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", default=str(settings.capture_input_dir))
    parser.add_argument("--output-dir", default=str(settings.parsed_output_dir))
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--interval", type=int, default=settings.capture_poll_seconds)
    parser.add_argument("--once", action="store_true", help="Parse pending files once then exit.")
    args = parser.parse_args()
    if args.interval <= 0:
        raise RuntimeError("--interval must be positive.")

    while True:
        try:
            parsed = parse_pending(args.input_dir, args.output_dir, args.tshark)
            print(f"Parsed {len(parsed)} capture(s).")
        except Exception as exc:
            print(f"[x] PCAP watch cycle failed: {exc}")
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
