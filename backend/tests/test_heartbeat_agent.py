"""Tests for the endpoint heartbeat client without network or MongoDB access."""

import unittest

from backend.app.workers.heartbeat_agent import EndpointHeartbeatAgent


class FakeResponse:
    text = "203.0.113.8"

    def raise_for_status(self):
        return None

    def json(self):
        return {"message": "Heartbeat received"}


class FakeSession:
    def __init__(self):
        self.post_url = None
        self.payload = None

    def get(self, _url, **_kwargs):
        return FakeResponse()

    def post(self, url, json, **_kwargs):
        self.post_url = url
        self.payload = json
        return FakeResponse()


class HeartbeatAgentTests(unittest.TestCase):
    def test_posts_heartbeat_to_server_api(self):
        session = FakeSession()
        agent = EndpointHeartbeatAgent(
            session,
            "http://127.0.0.1:5001/api/",
            "alpha",
            "test-host",
            local_ip_provider=lambda: "10.0.0.9",
            public_ip_provider=lambda _session: "203.0.113.8",
        )
        payload, result = agent.run_once()
        self.assertEqual(session.post_url, "http://127.0.0.1:5001/api/heartbeat")
        self.assertEqual(payload["company_id"], "alpha")
        self.assertEqual(session.payload["computer_name"], "test-host")
        self.assertEqual(result["message"], "Heartbeat received")
