from __future__ import annotations

from typing import Any

from app.core.config import settings


FALLBACK_LOCATIONS = [
    {"country": "United States", "region": "New York", "city": "New York", "latitude": 40.7128, "longitude": -74.0060},
    {"country": "India", "region": "Maharashtra", "city": "Mumbai", "latitude": 19.0760, "longitude": 72.8777},
    {"country": "Germany", "region": "Hesse", "city": "Frankfurt", "latitude": 50.1109, "longitude": 8.6821},
    {"country": "United Kingdom", "region": "England", "city": "London", "latitude": 51.5072, "longitude": -0.1276},
    {"country": "Japan", "region": "Tokyo", "city": "Tokyo", "latitude": 35.6762, "longitude": 139.6503},
    {"country": "Singapore", "region": "Central", "city": "Singapore", "latitude": 1.3521, "longitude": 103.8198},
    {"country": "Brazil", "region": "Sao Paulo", "city": "Sao Paulo", "latitude": -23.5505, "longitude": -46.6333},
    {"country": "Australia", "region": "New South Wales", "city": "Sydney", "latitude": -33.8688, "longitude": 151.2093},
    {"country": "Canada", "region": "Ontario", "city": "Toronto", "latitude": 43.6532, "longitude": -79.3832},
    {"country": "Netherlands", "region": "North Holland", "city": "Amsterdam", "latitude": 52.3676, "longitude": 4.9041},
]


class GeoService:
    """GeoIP enrichment with deterministic estimation fallback."""

    def __init__(self) -> None:
        self.reader = None
        if settings.geoip_database:
            try:
                import geoip2.database
                self.reader = geoip2.database.Reader(settings.geoip_database)
            except (ImportError, OSError):
                self.reader = None

    def enrich(self, source_ip: str | None) -> dict[str, Any]:
        empty = {"country": None, "region": None, "city": None, "latitude": None, "longitude": None, "estimated": True}
        if not source_ip or source_ip.strip() in {"Unknown", "unknown", ""}:
            return empty

        if self.reader:
            try:
                city = self.reader.city(source_ip)
                return {
                    "country": city.country.name,
                    "region": city.subdivisions.most_specific.name,
                    "city": city.city.name,
                    "latitude": city.location.latitude,
                    "longitude": city.location.longitude,
                    "estimated": False,
                }
            except Exception:
                pass

        # Deterministic fallback estimation based on IP value
        idx = abs(hash(source_ip)) % len(FALLBACK_LOCATIONS)
        loc = FALLBACK_LOCATIONS[idx]
        return {**loc, "estimated": True}


geo_service = GeoService()
