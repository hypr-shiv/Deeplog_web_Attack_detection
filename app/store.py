from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any


class EventStore:
    """Development repository; replace methods with PostgreSQL queries in deployment."""

    def __init__(self) -> None:
        self.analyses: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []

    def add_analysis(self, filename: str, events: list[dict[str, Any]]) -> dict[str, Any]:
        attacks = [event for event in events if event["prediction"] == "Attack"]
        risk_distribution = dict(Counter(event["risk"] for event in attacks))
        risk_distribution = {key: risk_distribution.get(key, 0) for key in ("Critical", "High", "Medium", "Low")}
        record = {"id": len(self.analyses) + 1, "file": filename, "date": datetime.now(timezone.utc).strftime("%b %d"), "created_at": datetime.now(timezone.utc).isoformat(), "status": "Done", "total_requests": len(events), "normal": len(events) - len(attacks), "attacks": len(attacks), "attack_rate": round(len(attacks) / len(events) * 100, 2) if events else 0, "risk_distribution": risk_distribution}
        self.analyses.insert(0, record)
        self.events[0:0] = [{**event, "analysis_id": record["id"]} for event in events]
        return record

    def list_events(self, filters: dict[str, str | None], limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        items = self.events
        for field, value in filters.items():
            if value:
                items = [event for event in items if value.lower() in str(event.get(field, "")).lower()]
        return items[offset:offset + limit], len(items)

    def event(self, event_id: int) -> dict[str, Any] | None:
        return next((event for event in self.events if event["id"] == event_id), None)

    def analytics(self) -> dict[str, Any]:
        attacks = [event for event in self.events if event["prediction"] == "Attack"]
        attack_types = Counter(
            event.get("attack_type") or "Other"
            for event in attacks
            if event.get("attack_type") not in (None, "None")
        )
        if not attack_types and attacks:
            attack_types["Suspicious Request"] = len(attacks)

        risk_distribution = dict(Counter(event["risk"] for event in attacks))
        risk_distribution = {key: risk_distribution.get(key, 0) for key in ("Critical", "High", "Medium", "Low")}

        return {
            "total_requests": len(self.events),
            "attacks": len(attacks),
            "normal": len(self.events) - len(attacks),
            "attack_rate": round(len(attacks) / len(self.events) * 100, 2) if self.events else 0,
            "risk_distribution": risk_distribution,
            "attack_types": dict(attack_types),
            "countries": dict(Counter(event.get("country") or "Unknown" for event in attacks)),
            "endpoints": dict(Counter(event.get("endpoint", "Unknown") for event in attacks)),
        }


store = EventStore()
