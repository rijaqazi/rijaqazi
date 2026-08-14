"""Smoke tests for the central backend application."""

import unittest

from backend.app.main import create_app


class HealthEndpointTests(unittest.TestCase):
    def test_health_endpoint(self):
        app = create_app()
        response = app.test_client().get("/api/v1/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")


if __name__ == "__main__":
    unittest.main()
