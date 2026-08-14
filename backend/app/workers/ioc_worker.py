"""Run IOC extraction and STIX bundle generation on an interval."""

import argparse
import time

from ..core.settings import settings
from ..integrations.taxii.paths import TAXII_BUNDLES_DIR
from ..services.intelligence.ioc_pipeline import generate_stix_bundles, update_iocs_from_log


def run_once(mode="all"):
    extracted = update_iocs_from_log(settings.detector_alert_log_path, settings.ioc_output_file) if mode in {"extract", "all"} else False
    bundles = generate_stix_bundles(settings.detector_alert_log_path, settings.ioc_output_file, settings.ioc_whitelist_file, TAXII_BUNDLES_DIR) if mode in {"stix", "all"} else []
    return extracted, bundles


def monitor(mode="all", interval=None):
    interval = interval or settings.ioc_poll_seconds
    while True:
        extracted, bundles = run_once(mode)
        if mode in {"extract", "all"}:
            print("[+] IOC document updated." if extracted else "[!] Detector alert log was not found.")
        if bundles:
            print(f"[+] Created {len(bundles)} STIX bundle(s).")
        time.sleep(interval)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("extract", "stix", "all"), default="all")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=settings.ioc_poll_seconds)
    args = parser.parse_args(argv)
    if args.interval <= 0:
        raise SystemExit("--interval must be positive.")
    if args.once:
        extracted, bundles = run_once(args.mode)
        print(f"IOC extraction: {'updated' if extracted else 'no source log'}; STIX bundles: {len(bundles)}")
    else:
        monitor(args.mode, args.interval)


if __name__ == "__main__":
    main()
