"""Download newly published rule-report archives from the upload service."""

import argparse
from pathlib import Path

from ...core.settings import settings


def download_new_reports(session, server_url, username, password, download_dir):
    """Download ZIP files not already present locally and return their names."""
    destination_dir = Path(download_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)
    base_url = server_url.rstrip("/")
    auth = (username, password)
    response = session.get(f"{base_url}/discover", auth=auth, timeout=10)
    response.raise_for_status()

    downloaded = []
    for entry in response.json().get("files", []):
        filename = Path(entry.get("filename", "")).name
        if not filename or filename != entry.get("filename") or not filename.lower().endswith(".zip"):
            continue
        destination = destination_dir / filename
        if destination.exists():
            continue

        response = session.get(f"{base_url}/download/{filename}", auth=auth, timeout=30)
        response.raise_for_status()
        destination.write_bytes(response.content)
        downloaded.append(filename)
    return downloaded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=str(settings.report_download_dir))
    args = parser.parse_args()

    if not settings.file_server_username or not settings.file_server_password:
        raise RuntimeError("FILE_SERVER_USERNAME and FILE_SERVER_PASSWORD must be set before downloading reports.")

    import requests

    print("Fetching file list from server...")
    downloaded = download_new_reports(
        requests,
        settings.file_server_url,
        settings.file_server_username,
        settings.file_server_password,
        args.output_dir,
    )
    for filename in downloaded:
        print(f"[+] Saved: {filename}")
    print(f"All new ZIP files downloaded to: {Path(args.output_dir).resolve()}")


if __name__ == "__main__":
    main()
