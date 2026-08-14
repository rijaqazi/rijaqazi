"""Push and pull clients for the migrated TAXII integration."""

import argparse
import json
import re
import time
from datetime import datetime

import requests
from requests.auth import HTTPBasicAuth

from ...core.settings import settings
from .paths import IOC_PULL_OUTPUT_DIR, TAXII_BUNDLES_DIR


def _credentials():
    if not settings.taxii_admin_username or not settings.taxii_admin_password:
        raise RuntimeError("TAXII_ADMIN_USERNAME and TAXII_ADMIN_PASSWORD must be set.")
    return HTTPBasicAuth(settings.taxii_admin_username, settings.taxii_admin_password)


def _headers():
    return {
        "Content-Type": "application/json",
        "Accept": "application/taxii+json;version=2.1",
    }


def create_safe_filename(name):
    cleaned = re.sub(r"[^\w\s-]", "", name)
    return re.sub(r"[-\s]+", "_", cleaned)[:50]


def pull_iocs():
    """Download new indicator objects from the configured TAXII collection."""
    IOC_PULL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    existing_ids = set()
    for path in IOC_PULL_OUTPUT_DIR.glob("*.json"):
        try:
            existing_ids.add(json.loads(path.read_text(encoding="utf-8")).get("id"))
        except (OSError, json.JSONDecodeError):
            continue

    response = requests.get(
        settings.taxii_server_url, auth=_credentials(), headers=_headers(), timeout=30
    )
    response.raise_for_status()
    bundles = response.json().get("objects", [])
    saved = skipped = 0

    for bundle in bundles:
        objects = bundle.get("objects", []) if bundle.get("type") == "bundle" else [bundle]
        for indicator in objects:
            if indicator.get("type") != "indicator" or indicator.get("id") in existing_ids:
                skipped += 1
                continue
            indicator_id = indicator.get("id", "unknown_id")
            name = create_safe_filename(indicator.get("name", "unknown_ioc"))
            ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", indicator.get("pattern", ""))
            ip_address = ip_match.group(0) if ip_match else "unknown_ip"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"IOC_{ip_address}_{name}_{indicator_id.replace('indicator--', '')}_{timestamp}.json"
            (IOC_PULL_OUTPUT_DIR / filename).write_text(
                json.dumps(indicator, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            existing_ids.add(indicator_id)
            saved += 1

    print(f"[+] Saved {saved} new IOCs; skipped {skipped}. Output: {IOC_PULL_OUTPUT_DIR}")
    return saved, skipped


def _load_uploaded_files():
    state_file = TAXII_BUNDLES_DIR / ".uploaded_files.txt"
    if not state_file.is_file():
        return set()
    return {line.strip() for line in state_file.read_text(encoding="utf-8").splitlines() if line.strip()}


def _save_uploaded_files(uploaded_files):
    state_file = TAXII_BUNDLES_DIR / ".uploaded_files.txt"
    state_file.write_text("\n".join(sorted(uploaded_files)) + "\n", encoding="utf-8")


def push_bundles():
    """Upload new valid STIX bundles and persist their local upload state."""
    TAXII_BUNDLES_DIR.mkdir(parents=True, exist_ok=True)
    uploaded_files = _load_uploaded_files()
    uploaded = failed = 0

    for path in sorted(TAXII_BUNDLES_DIR.glob("*.json")):
        if path.name in uploaded_files:
            continue
        try:
            bundle = json.loads(path.read_text(encoding="utf-8"))
            response = requests.post(
                settings.taxii_server_url, auth=_credentials(), headers=_headers(), json=bundle, timeout=30
            )
            response.raise_for_status()
        except (OSError, json.JSONDecodeError, requests.RequestException) as exc:
            print(f"[x] Failed to upload {path.name}: {exc}")
            failed += 1
            continue
        uploaded_files.add(path.name)
        uploaded += 1
        print(f"[+] Uploaded {path.name}")

    _save_uploaded_files(uploaded_files)
    print(f"[+] Upload complete: {uploaded} succeeded, {failed} failed.")
    return uploaded, failed


def monitor_pull(interval=30):
    while True:
        pull_iocs()
        time.sleep(interval)


def monitor_push(interval=30):
    while True:
        push_bundles()
        time.sleep(interval)


def pull_main(argv=None):
    parser = argparse.ArgumentParser(description="Pull IOCs from TAXII.")
    parser.add_argument("--monitor", action="store_true", help="Poll continuously every 30 seconds.")
    args = parser.parse_args(argv)
    monitor_pull() if args.monitor else pull_iocs()


def push_main(argv=None):
    parser = argparse.ArgumentParser(description="Push STIX bundles to TAXII.")
    parser.add_argument("--once", action="store_true", help="Upload once instead of monitoring.")
    args = parser.parse_args(argv)
    push_bundles() if args.once else monitor_push()
