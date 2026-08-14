"""Project-relative paths for code migrated into the backend package."""

from pathlib import Path

from .settings import PROJECT_ROOT


DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = DATA_DIR / "logs"
PCAPS_DIR = DATA_DIR / "pcaps"
GENERATED_DIR = DATA_DIR / "generated"
STIX_DIR = DATA_DIR / "stix"


def ensure_data_directories() -> None:
    """Create local runtime directories on demand, not during import."""
    for directory in (DATA_DIR, LOGS_DIR, PCAPS_DIR, GENERATED_DIR, STIX_DIR):
        directory.mkdir(parents=True, exist_ok=True)
