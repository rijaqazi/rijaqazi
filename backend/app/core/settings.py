"""Central configuration for services migrated into the backend package."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def load_env_file(path: Optional[Union[str, Path]] = None) -> bool:
    """Load simple .env values without overriding values already exported."""
    env_path = Path(path) if path else PROJECT_ROOT / ".env"
    if not env_path.is_file():
        return False

    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"\"", "'"}:
            value = value[1:-1]
        if key:
            os.environ.setdefault(key, value)
    return True


def _positive_int(name: str, default: int) -> int:
    value = os.getenv(name, str(default))
    try:
        parsed = int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive integer.") from exc
    if parsed <= 0:
        raise RuntimeError(f"{name} must be a positive integer.")
    return parsed


@dataclass(frozen=True)
class Settings:
    """Environment-backed settings shared by migrated services."""

    project_root: Path
    mongodb_uri: Optional[str]
    taxii_admin_username: Optional[str]
    taxii_admin_password: Optional[str]
    taxii_user_password: Optional[str]
    taxii_server_url: str
    taxii_bind_host: str
    taxii_port: int
    file_server_url: str
    file_server_username: Optional[str]
    file_server_password: Optional[str]
    backend_bind_host: str
    backend_port: int
    heartbeat_bind_host: str
    file_server_bind_host: str
    max_upload_bytes: int
    max_taxii_request_bytes: int
    auth_max_failures: int
    auth_failure_window_seconds: int
    cvss_poll_seconds: int

    @classmethod
    def from_environment(cls) -> "Settings":
        return cls(
            project_root=PROJECT_ROOT,
            mongodb_uri=os.getenv("MONGODB_URI"),
            taxii_admin_username=os.getenv("TAXII_ADMIN_USERNAME"),
            taxii_admin_password=os.getenv("TAXII_ADMIN_PASSWORD"),
            taxii_user_password=os.getenv("TAXII_USER_PASSWORD"),
            taxii_server_url=os.getenv("TAXII_SERVER_URL", "http://127.0.0.1:5002"),
            taxii_bind_host=os.getenv("TAXII_BIND_HOST", "127.0.0.1"),
            taxii_port=_positive_int("TAXII_PORT", 5002),
            file_server_url=os.getenv("FILE_SERVER_URL", "http://127.0.0.1:5005"),
            file_server_username=os.getenv("FILE_SERVER_USERNAME"),
            file_server_password=os.getenv("FILE_SERVER_PASSWORD"),
            backend_bind_host=os.getenv("BACKEND_BIND_HOST", "127.0.0.1"),
            backend_port=_positive_int("BACKEND_PORT", 8000),
            heartbeat_bind_host=os.getenv("HEARTBEAT_BIND_HOST", "127.0.0.1"),
            file_server_bind_host=os.getenv("FILE_SERVER_BIND_HOST", "127.0.0.1"),
            max_upload_bytes=_positive_int("MAX_UPLOAD_BYTES", 16 * 1024 * 1024),
            max_taxii_request_bytes=_positive_int("MAX_TAXII_REQUEST_BYTES", 5 * 1024 * 1024),
            auth_max_failures=_positive_int("AUTH_MAX_FAILURES", 5),
            auth_failure_window_seconds=_positive_int("AUTH_FAILURE_WINDOW_SECONDS", 300),
            cvss_poll_seconds=_positive_int("CVSS_POLL_SECONDS", 20),
        )


load_env_file()
settings = Settings.from_environment()
