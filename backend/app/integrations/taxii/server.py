"""TAXII 2.1 service migrated from the legacy ``ioc`` directory."""

import hmac
import json
import os
import threading
import time
from functools import wraps

from flask import Flask, Response, jsonify, request

from ...core.settings import settings
from .paths import TAXII_BUNDLES_DIR


COLLECTION_ID = "91a7b528-80eb-42ed-a74d-c6fbd5a26116"
TAXII_HOST = settings.taxii_bind_host
TAXII_PORT = settings.taxii_port
BASE_URL = f"http://{TAXII_HOST}:{TAXII_PORT}"
BUNDLES_DIR = TAXII_BUNDLES_DIR

if not settings.taxii_admin_username or not settings.taxii_admin_password:
    raise RuntimeError(
        "TAXII_ADMIN_USERNAME and TAXII_ADMIN_PASSWORD must be set before starting the TAXII server."
    )


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = settings.max_taxii_request_bytes
app.config["JSON_SORT_KEYS"] = False
taxii_objects = {COLLECTION_ID: []}
auth_failures = {}
auth_failures_lock = threading.Lock()


@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def check_auth(username, password):
    return hmac.compare_digest(username, settings.taxii_admin_username) and hmac.compare_digest(
        password, settings.taxii_admin_password
    )


def auth_rate_limited(client_ip):
    now = time.monotonic()
    with auth_failures_lock:
        failures = [
            timestamp
            for timestamp in auth_failures.get(client_ip, [])
            if now - timestamp < settings.auth_failure_window_seconds
        ]
        auth_failures[client_ip] = failures
        return len(failures) >= settings.auth_max_failures


def record_auth_failure(client_ip):
    with auth_failures_lock:
        auth_failures.setdefault(client_ip, []).append(time.monotonic())


def clear_auth_failures(client_ip):
    with auth_failures_lock:
        auth_failures.pop(client_ip, None)


def requires_auth(view):
    @wraps(view)
    def decorated(*args, **kwargs):
        auth = request.authorization
        client_ip = request.remote_addr or "unknown"
        if auth_rate_limited(client_ip):
            return jsonify({"error": "Too many authentication attempts"}), 429
        if not auth or not check_auth(auth.username, auth.password):
            record_auth_failure(client_ip)
            return jsonify({"error": "Unauthorized"}), 401
        clear_auth_failures(client_ip)
        return view(*args, **kwargs)

    return decorated


def is_valid_stix_bundle(payload):
    if not isinstance(payload, dict) or payload.get("type") != "bundle":
        return False
    return isinstance(payload.get("objects"), list) and all(
        isinstance(obj, dict)
        and isinstance(obj.get("id"), str)
        and isinstance(obj.get("type"), str)
        for obj in payload["objects"]
    )


def bundle_files():
    if not BUNDLES_DIR.is_dir():
        return []
    return sorted(BUNDLES_DIR.glob("*.json"))


def read_bundles():
    bundles = []
    for bundle_file in bundle_files():
        try:
            with bundle_file.open(encoding="utf-8") as handle:
                bundles.append((bundle_file.name, json.load(handle)))
        except (OSError, json.JSONDecodeError):
            continue
    return bundles


def load_existing_bundles():
    """Load saved STIX objects into memory when the TAXII service starts."""
    count = 0
    for _, bundle in read_bundles():
        for obj in bundle.get("objects", []):
            if isinstance(obj, dict):
                taxii_objects[COLLECTION_ID].append(obj)
                count += 1
    print(f"[+] Loaded {count} STIX objects from {BUNDLES_DIR}.")


def taxii_response(data, status=200):
    return Response(
        json.dumps(data), status=status, mimetype="application/taxii+json; version=2.1"
    )


@app.get("/")
@requires_auth
def index():
    summaries = []
    for filename, bundle in read_bundles():
        for obj in bundle.get("objects", []):
            summaries.append(
                {
                    "file": filename,
                    "id": obj.get("id"),
                    "type": obj.get("type"),
                    "created": obj.get("created"),
                    "description": obj.get("description", "N/A"),
                }
            )
    return jsonify({"bundles": summaries})


@app.get("/full")
@requires_auth
def full_iocs():
    all_iocs = []
    for filename, bundle in read_bundles():
        for obj in bundle.get("objects", []):
            if isinstance(obj, dict):
                all_iocs.append({**obj, "file": filename})
    return jsonify({"iocs": all_iocs})


@app.route(f"/api1/collections/{COLLECTION_ID}/objects/", methods=["GET", "POST"])
@requires_auth
def bundle_collection():
    if request.method == "GET":
        return jsonify({"collection_id": COLLECTION_ID, "objects": [bundle for _, bundle in read_bundles()]})
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    bundle = request.get_json(silent=True)
    if not is_valid_stix_bundle(bundle):
        return jsonify({"error": "Request must be a valid STIX bundle"}), 400
    taxii_objects[COLLECTION_ID].extend(bundle["objects"])
    return jsonify({"message": "STIX bundle received successfully!"}), 202


@app.get("/taxii2/")
def discovery():
    return taxii_response(
        {
            "title": "IOC TAXII Server",
            "description": "TAXII 2.1 Server for IOC Sharing",
            "contact": "admin@localhost",
            "default": f"{BASE_URL}/api1/",
            "api_roots": [f"{BASE_URL}/api1/"],
        }
    )


@app.get("/api1/")
def api_root():
    return taxii_response(
        {
            "title": "IOC API Root",
            "description": "Primary API Root for IOC Collections",
            "versions": ["taxii-2.1"],
            "max_content_length": settings.max_taxii_request_bytes,
        }
    )


@app.get("/api1/collections/")
@requires_auth
def collections():
    return taxii_response(
        {
            "collections": [
                {
                    "id": COLLECTION_ID,
                    "title": "IOC Collection",
                    "description": "Collection for sharing IOCs",
                    "can_read": True,
                    "can_write": True,
                    "media_types": ["application/stix+json; version=2.1"],
                    "url": f"{BASE_URL}/api1/collections/{COLLECTION_ID}/",
                }
            ]
        }
    )


@app.route(f"/api1/collections/{COLLECTION_ID}/objects", methods=["GET", "POST"])
@requires_auth
def taxii_objects_handler():
    if request.method == "GET":
        return taxii_response({"objects": taxii_objects[COLLECTION_ID], "more": False})
    if not request.is_json:
        return taxii_response({"error": "Bad JSON"}, 400)
    bundle = request.get_json(silent=True)
    if not is_valid_stix_bundle(bundle):
        return taxii_response({"error": "Request must be a valid STIX bundle"}, 400)
    taxii_objects[COLLECTION_ID].extend(bundle["objects"])
    return taxii_response({"message": "STIX received"}, 202)


@app.get(f"/api1/collections/{COLLECTION_ID}/objects/<object_id>/")
@requires_auth
def get_single(object_id):
    for obj in taxii_objects[COLLECTION_ID]:
        if obj.get("id") == object_id:
            return taxii_response(obj)
    return taxii_response({"error": "Object not found"}, 404)


def main():
    if TAXII_HOST not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError(
            "Do not expose the Flask development server. Use a production WSGI server behind TLS."
        )
    load_existing_bundles()
    print(f"[+] TAXII server listening on {BASE_URL}")
    app.run(host=TAXII_HOST, port=TAXII_PORT, debug=False)


if __name__ == "__main__":
    main()
