"""Database-free tests for heartbeat business logic."""

import unittest

from backend.app.services.alerts.heartbeat_service import HeartbeatService


class FakeHeartbeatRepository:
    def __init__(self):
        self.calls = []

    def record_heartbeat(self, company_id, computer_name, ip_address, public_ip):
        self.calls.append((company_id, computer_name, ip_address, public_ip))
        from datetime import datetime

        return "added", datetime.now()

    def status(self):
        return {"mongodb": "connected", "active_ips": 1, "total_heartbeats": 1}

    def recent_heartbeats(self):
        return []

    def active_ips(self):
        return []


class HeartbeatServiceTests(unittest.TestCase):
    def setUp(self):
        self.repository = FakeHeartbeatRepository()
        self.service = HeartbeatService(self.repository)

    def test_processes_valid_heartbeat(self):
        result = self.service.process({"company_id": "alpha", "ip_address": "10.0.0.1"})
        self.assertEqual(result["action"], "added")
        self.assertEqual(self.repository.calls[0][0], "alpha")

    def test_rejects_missing_required_fields(self):
        with self.assertRaises(ValueError):
            self.service.process({"company_id": "alpha"})
