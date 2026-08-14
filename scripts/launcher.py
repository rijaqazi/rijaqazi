#!/usr/bin/env python3
"""Start selected local ThreatSentinel services from the project root."""

import argparse
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.settings import load_env_file

SERVICE_DEFINITIONS = {
    "upload": {
        "label": "secure upload server",
        "script": PROJECT_ROOT / "Rule_Generation" / "secure_server.py",
        "cwd": PROJECT_ROOT / "Rule_Generation",
        "port": 5005,
    },
    "heartbeat": {
        "label": "heartbeat server",
        "script": PROJECT_ROOT / "agent" / "heartbeat_server.py",
        "cwd": PROJECT_ROOT / "agent",
        "port": 5001,
    },
    "taxii": {
        "label": "TAXII server",
        "script": PROJECT_ROOT / "ioc" / "taxi_server.py",
        "cwd": PROJECT_ROOT / "ioc",
        "port": 5002,
    },
}


def port_is_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def start_service(name):
    service = SERVICE_DEFINITIONS[name]
    if name == "upload" and not (service["cwd"] / "creds.json").is_file():
        raise RuntimeError(
            "Upload credentials are not initialized. Run 'python3 Rule_Generation/secure_server.py' "
            "once, create the credentials, stop it, then rerun the launcher."
        )
    if not port_is_available(service["port"]):
        raise RuntimeError(f"Port {service['port']} is already in use; {service['label']} was not started.")

    print(f"[+] Starting {service['label']} on port {service['port']}...")
    kwargs = {
        "cwd": service["cwd"],
        "env": os.environ.copy(),
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    process = subprocess.Popen([sys.executable, str(service["script"])], **kwargs)
    time.sleep(0.5)
    if process.poll() is not None:
        raise RuntimeError(f"{service['label']} exited immediately with code {process.returncode}.")
    print(f"    PID {process.pid} | http://127.0.0.1:{service['port']}/")
    return process


def stop_process(process):
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "services",
        nargs="*",
        choices=[*SERVICE_DEFINITIONS, "all"],
        default=["all"],
        help="Services to start (default: all).",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if not load_env_file(PROJECT_ROOT / ".env"):
        print(f"[!] No .env file at {PROJECT_ROOT / '.env'}; using the current shell environment.")
    selected = list(SERVICE_DEFINITIONS) if "all" in args.services else args.services
    processes = []
    try:
        for service in selected:
            processes.append(start_service(service))
        print("[+] Selected services are running. Press Ctrl+C to stop them.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Stopping services...")
    finally:
        for process in reversed(processes):
            stop_process(process)
        if processes:
            print("[+] Services stopped.")


if __name__ == "__main__":
    main()
