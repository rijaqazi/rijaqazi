#!/usr/bin/env python3
"""Compatibility entry point for migrated heartbeat API routes."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.api.v1.heartbeats import create_legacy_heartbeat_app
from backend.app.core.settings import settings


app = create_legacy_heartbeat_app()


if __name__ == "__main__":
    if settings.heartbeat_bind_host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError(
            "Do not expose the Flask development server. Use a production WSGI server behind TLS."
        )
    app.run(host=settings.heartbeat_bind_host, port=5001, debug=False)
