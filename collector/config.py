"""Configuration settings for NetSight Python Collector."""

from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

ENGINE_HOST = os.getenv("ENGINE_HOST", "127.0.0.1")
ENGINE_PORT = int(os.getenv("ENGINE_PORT", "9999"))
COLLECTOR_HOST = os.getenv("COLLECTOR_HOST", "127.0.0.1")
COLLECTOR_PORT = int(os.getenv("COLLECTOR_PORT", "8000"))
TESTING = os.getenv("TESTING", "0") == "1"

DB_PATH = Path(os.getenv("DB_PATH", str(PROJECT_ROOT / "netsight.db")))
RULES_PATH = Path(os.getenv("RULES_PATH", str(PROJECT_ROOT / "rules.json")))

# Path to the compiled C++ engine binary
if os.name == "nt":
    DEFAULT_BINARY = PROJECT_ROOT / "engine" / "build" / "Release" / "netsight-engine.exe"
else:
    DEFAULT_BINARY = PROJECT_ROOT / "engine" / "build" / "netsight-engine"

raw_binary = os.getenv("ENGINE_BINARY")
if raw_binary:
    candidate = Path(raw_binary).resolve()
    if candidate.name not in ("netsight-engine", "netsight-engine.exe"):
        raise ValueError(
            f"Invalid ENGINE_BINARY filename '{candidate.name}': must be 'netsight-engine' or 'netsight-engine.exe'"
        )
    ENGINE_BINARY = candidate
else:
    ENGINE_BINARY = DEFAULT_BINARY

UPLOAD_DIR = PROJECT_ROOT / "uploads"
OUTPUT_DIR = PROJECT_ROOT / "outputs"

UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    if origin.strip()
]

API_KEY = os.getenv("NETSIGHT_API_KEY", "")
ENABLE_DOCS = os.getenv("ENABLE_DOCS", "0").lower() in ("1", "true")
