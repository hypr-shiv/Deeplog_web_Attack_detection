from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    app_name: str = "DeepLog API"
    api_prefix: str = "/api/v1"
    model_version: str = "1.0.0"
    detection_threshold: float = 0.45
    database_url: str = os.getenv("DATABASE_URL", "")
    geoip_database: str = os.getenv("GEOIP_DATABASE", "")
    jwt_secret: str = os.getenv("JWT_SECRET", "deeplog-development-secret")
    upload_limit_bytes: int = 50 * 1024 * 1024
    root_dir: Path = Path(__file__).resolve().parents[2]


settings = Settings()
