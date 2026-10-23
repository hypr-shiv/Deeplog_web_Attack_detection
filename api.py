"""Compatibility entry point for `uvicorn api:app`."""

from app.main import app

__all__ = ["app"]
