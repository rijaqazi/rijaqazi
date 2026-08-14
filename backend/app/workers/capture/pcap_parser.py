"""Convert a PCAP file into a tshark JSON export."""

import argparse
import subprocess
from pathlib import Path


def parse_pcap(pcap_path, output_dir=None, tshark_executable="tshark", runner=subprocess.run):
    """Run tshark without a shell and return the written JSON file path."""
    source = Path(pcap_path)
    if not source.is_file():
        raise FileNotFoundError(f"PCAP file not found: {source}")
    destination_dir = Path(output_dir) if output_dir else source.parent
    destination_dir.mkdir(parents=True, exist_ok=True)
    output = destination_dir / f"{source.stem}_parsed.json"
    result = runner([tshark_executable, "-r", str(source), "-T", "json"], capture_output=True, text=True, check=True)
    output.write_text(result.stdout, encoding="utf-8")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap_file", help="Path to a .pcap or .pcapng file.")
    parser.add_argument("--output-dir", help="Directory for the parsed JSON output.")
    parser.add_argument("--tshark", default="tshark", help="tshark executable path or command.")
    args = parser.parse_args()
    try:
        output = parse_pcap(args.pcap_file, args.output_dir, args.tshark)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"PCAP parsing failed: {exc}") from exc
    print(f"Parsed data saved to: {output}")


if __name__ == "__main__":
    main()
