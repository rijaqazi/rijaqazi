# Running ThreatSentinel

Activate the project environment and configure `.env` before starting any service.

```bash
source .venv/bin/activate
python3 scripts/launcher.py all
```

The launcher starts the existing upload, heartbeat, and TAXII services. Stop all services it started with `Ctrl+C`.

## Central backend API

The new backend application currently provides a health endpoint while legacy functionality is migrated.

```bash
python3 -m backend.app.main
curl http://127.0.0.1:8000/api/v1/health
```

The expected response is JSON with `"status": "ok"`.
