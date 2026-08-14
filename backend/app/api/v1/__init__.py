"""Version 1 API routes."""

from .health import router as health_router
from .heartbeats import create_heartbeat_blueprint


def register_routes(app):
    """Register version 1 routes on the central backend application."""
    app.register_blueprint(health_router, url_prefix="/api/v1")
    app.register_blueprint(create_heartbeat_blueprint(), url_prefix="/api/v1")
