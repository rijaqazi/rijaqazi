"""Health endpoint for the central backend application."""

from flask import Blueprint, jsonify


router = Blueprint("health", __name__)


@router.get("/health")
def health():
    return jsonify({"status": "ok", "service": "threatsentinel-backend", "api_version": "v1"})
