"""Endpoint-side client that reports a periodic heartbeat to the backend."""

import argparse
import socket
import time
from datetime import datetime

from ..core.settings import settings


def get_local_ip_address():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


def get_public_ip_address(session):
    try:
        response = session.get("https://api.ipify.org", timeout=5)
        response.raise_for_status()
        return response.text.strip()
    except Exception:
        return None


class EndpointHeartbeatAgent:
    """Collect endpoint network identity and POST it to the heartbeat API."""

    def __init__(
        self,
        session,
        server_url,
        company_id,
        computer_name=None,
        local_ip_provider=get_local_ip_address,
        public_ip_provider=get_public_ip_address,
    ):
        self.session = session
        self.server_url = server_url.rstrip("/")
        self.company_id = company_id
        self.computer_name = computer_name or socket.gethostname()
        self.local_ip_provider = local_ip_provider
        self.public_ip_provider = public_ip_provider

    def run_once(self):
        local_ip = self.local_ip_provider()
        public_ip = self.public_ip_provider(self.session)
        payload = {
            "company_id": self.company_id,
            "computer_name": self.computer_name,
            "ip_address": local_ip,
            "public_ip": public_ip,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": "endpoint_agent",
        }
        response = self.session.post(f"{self.server_url}/heartbeat", json=payload, timeout=10)
        response.raise_for_status()
        return payload, response.json()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default=settings.heartbeat_server_url, help="Heartbeat API base URL.")
    parser.add_argument("--company-id", default=settings.agent_company_id)
    parser.add_argument("--interval", type=int, default=settings.agent_heartbeat_seconds)
    parser.add_argument("--once", action="store_true", help="Send one heartbeat then exit.")
    args = parser.parse_args()
    if args.interval <= 0:
        raise RuntimeError("--interval must be positive.")

    import requests

    agent = EndpointHeartbeatAgent(requests, args.server, args.company_id)
    while True:
        try:
            payload, result = agent.run_once()
            print(f"[+] Heartbeat sent for {payload['ip_address']}: {result.get('message', 'accepted')}")
        except Exception as exc:
            print(f"[x] Heartbeat failed: {exc}")
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
