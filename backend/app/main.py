"""Central backend application entry point.

Legacy services remain independently runnable during the gradual migration.
"""

from flask import Flask, jsonify

from .api.v1 import register_routes
from .core.paths import ensure_data_directories
from .core.settings import settings


def create_app() -> Flask:
    """Create the central backend API without starting legacy workers."""
    ensure_data_directories()
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = settings.max_taxii_request_bytes
    app.config["JSON_SORT_KEYS"] = False

    @app.after_request
    def add_security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.get("/")
    def index():
        return jsonify({"service": "ThreatSentinel", "api": "/api/v1"})

    register_routes(app)
    return app


app = create_app()


if __name__ == "__main__":
    if settings.backend_bind_host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError(
            "Do not expose the Flask development server. Use a production WSGI server behind TLS."
        )
    app.run(host=settings.backend_bind_host, port=settings.backend_port, debug=False)
