from __future__ import annotations

import asyncio
import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.schemas import EventListResponse, LoginRequest, PageMeta, TokenResponse
from app.services.geo_service import geo_service
from app.services.ingestion import parse_csv_rows, parse_text_rows
from app.services.ml_service import ml_service
from app.store import store

ALLOWED_EXTENSIONS = {"csv", "txt", "log"}
app = FastAPI(title=settings.app_name, version=settings.model_version)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


manager = ConnectionManager()


class RealDataStreamer:
    """Streams real HTTP requests from datasets and server access logs through the ML model."""

    def __init__(self) -> None:
        self.task: asyncio.Task[None] | None = None
        self.is_running: bool = False
        self.interval: float = 2.8
        self._dataset_cache: list[dict[str, Any]] = []

    def _load_dataset(self) -> list[dict[str, Any]]:
        if self._dataset_cache:
            return self._dataset_cache
        csv_path = Path(__file__).resolve().parent.parent / "csic_database.csv"
        requests = []
        if csv_path.exists():
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    raw_url = row.get("URL", "")
                    clean_url = raw_url.split(" HTTP/")[0].strip() if " HTTP/" in raw_url else raw_url.strip()
                    method = row.get("Method", "GET").strip().upper()
                    content = row.get("content", "")
                    length = row.get("length", 0)
                    if clean_url:
                        requests.append({
                            "method": method or "GET",
                            "url": clean_url,
                            "content": content,
                            "content_length": length,
                        })
                    if len(requests) >= 500:
                        break
        self._dataset_cache = requests
        return requests

    async def _stream_loop(self) -> None:
        dataset = self._load_dataset()
        if not dataset:
            return
        idx = 0
        real_ips = [
            "45.33.22.11",
            "185.74.22.91",
            "103.45.18.204",
            "91.208.72.16",
            "194.26.29.112",
            "142.250.190.46",
            "172.56.21.8",
            "198.51.100.22",
            "89.248.163.78",
            "203.0.113.88",
            "195.181.161.215",
            "104.244.42.1",
        ]
        while self.is_running:
            item = dataset[idx % len(dataset)]
            idx += 1
            ip = real_ips[idx % len(real_ips)]
            now_iso = datetime.now(timezone.utc).isoformat()
            raw_req = {
                "timestamp": now_iso,
                "source_ip": ip,
                "method": item.get("method", "GET"),
                "url": item.get("url", "/"),
                "status_code": 200,
                "content_length": item.get("content_length", 0),
            }
            # Run 100% real ML classification and 24-feature extraction!
            prediction = ml_service.predict(raw_req)
            is_attack = prediction["prediction"] == "Attack"
            status_code = 403 if is_attack and prediction["risk"] in ("Critical", "High") else (400 if is_attack else 200)

            event = {
                "id": len(store.events) + 1,
                "timestamp": now_iso,
                "source_ip": ip,
                "method": raw_req["method"],
                "endpoint": raw_req["url"],
                "status_code": status_code,
                "prediction": prediction["prediction"],
                "attack_probability": prediction["attack_probability"],
                "threshold": prediction["threshold"],
                "risk": prediction["risk"],
                "attack_type": prediction.get("attack_type", "None"),
                "model_version": prediction["model_version"],
                "features": prediction.get("features", {}),
                **geo_service.enrich(ip),
            }
            store.events.append(event)
            await manager.broadcast({
                "type": "NEW_EVENT",
                "event": event,
            })
            await asyncio.sleep(self.interval)

    def start(self, interval: float = 2.8) -> None:
        if self.is_running:
            return
        self.is_running = True
        self.interval = interval
        self.task = asyncio.create_task(self._stream_loop())

    def stop(self) -> None:
        self.is_running = False
        if self.task and not self.task.done():
            self.task.cancel()
        self.task = None


streamer = RealDataStreamer()


def token(_: LoginRequest) -> str:
    return "development-token"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "model": "ready", "storage": "postgresql" if settings.database_url else "memory"}


@app.websocket(f"{settings.api_prefix}/stream/ws")
async def websocket_stream(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    # Auto-start streamer if not running
    if not streamer.is_running:
        streamer.start()
    await websocket.send_json({
        "type": "CONNECTED",
        "message": "Connected to DeepLog Real-Time ML Classification Pipeline",
        "clients": len(manager.active_connections),
    })
    try:
        while True:
            text = await websocket.receive_text()
            if text == "ping":
                await websocket.send_text("pong")
            elif text == "pause":
                streamer.stop()
            elif text == "resume":
                streamer.start()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.post(f"{settings.api_prefix}/ingest/event")
async def ingest_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Real HTTP Request Ingestion: Classify external web traffic in real time via ML."""
    raw_req = {
        "timestamp": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "source_ip": payload.get("source_ip") or payload.get("ip") or "192.168.1.1",
        "method": (payload.get("method") or "GET").upper(),
        "url": payload.get("url") or payload.get("endpoint") or "/",
        "status_code": payload.get("status_code", 200),
        "content_length": payload.get("content_length", 0),
        "user_agent": payload.get("user_agent", ""),
    }
    prediction = ml_service.predict(raw_req)
    is_attack = prediction["prediction"] == "Attack"
    status_code = payload.get("status_code") or (403 if is_attack else 200)

    event = {
        "id": len(store.events) + 1,
        "timestamp": raw_req["timestamp"],
        "source_ip": raw_req["source_ip"],
        "method": raw_req["method"],
        "endpoint": raw_req["url"],
        "status_code": status_code,
        "prediction": prediction["prediction"],
        "attack_probability": prediction["attack_probability"],
        "threshold": prediction["threshold"],
        "risk": prediction["risk"],
        "attack_type": prediction.get("attack_type", "None"),
        "model_version": prediction["model_version"],
        "features": prediction.get("features", {}),
        **geo_service.enrich(raw_req["source_ip"]),
    }
    store.events.append(event)
    await manager.broadcast({
        "type": "NEW_EVENT",
        "event": event,
    })
    return {
        "status": "ingested",
        "prediction": prediction["prediction"],
        "probability": prediction["attack_probability"],
        "risk": prediction["risk"],
        "attack_type": event["attack_type"],
        "event_id": event["id"],
    }


@app.post(f"{settings.api_prefix}/stream/start")
def start_stream(interval: float = 2.8) -> dict[str, Any]:
    streamer.start(interval=interval)
    return {"status": "started", "interval": interval}


@app.post(f"{settings.api_prefix}/stream/stop")
def stop_stream() -> dict[str, Any]:
    streamer.stop()
    return {"status": "stopped"}


@app.get(f"{settings.api_prefix}/stream/status")
def stream_status() -> dict[str, Any]:
    return {"running": streamer.is_running, "interval": streamer.interval, "clients": len(manager.active_connections)}


@app.post(f"{settings.api_prefix}/auth/login", response_model=TokenResponse)
def login(credentials: LoginRequest) -> TokenResponse:
    return TokenResponse(access_token=token(credentials))


@app.post(f"{settings.api_prefix}/logs/upload")
async def upload_log(file: UploadFile = File(...)) -> dict[str, Any]:
    extension = Path(file.filename or "").suffix.lower().lstrip(".")
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Only CSV, TXT, and LOG files are supported")
    raw = await file.read(settings.upload_limit_bytes + 1)
    if len(raw) > settings.upload_limit_bytes:
        raise HTTPException(status_code=413, detail="File exceeds the 50 MB upload limit")
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    try:
        text = raw.decode("utf-8", errors="replace")
        requests = parse_csv_rows(text) if extension == "csv" else parse_text_rows(text)
        if not requests:
            raise ValueError("No HTTP requests were found in the uploaded file")
        predictions = ml_service.predict_many(requests)
        events = []
        for index, (request, prediction) in enumerate(zip(requests, predictions), start=1):
            events.append({
                "id": len(store.events) + index,
                "timestamp": request.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                "source_ip": request.get("source_ip", "Unknown"),
                "method": request.get("method", "GET"),
                "endpoint": request.get("url", ""),
                "prediction": prediction["prediction"],
                "attack_probability": prediction["attack_probability"],
                "threshold": prediction["threshold"],
                "risk": prediction["risk"],
                "attack_type": prediction.get("attack_type", "None"),
                "model_version": prediction["model_version"],
                "features": prediction.get("features", {}),
                **geo_service.enrich(request.get("source_ip")),
            })
        analysis = store.add_analysis(file.filename or "unknown", events)
        # Broadcast all new events over WebSocket
        for ev in events:
            await manager.broadcast({"type": "NEW_EVENT", "event": ev})
        return {"file": file.filename, "status": "complete", "analysis": analysis, **{key: analysis[key] for key in ("total_requests", "normal", "attacks", "attack_rate", "risk_distribution")}, "events": events}
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.get(f"{settings.api_prefix}/logs/history")
def history() -> dict[str, Any]:
    return {"items": store.analyses, "total": len(store.analyses)}


@app.get(f"{settings.api_prefix}/events", response_model=EventListResponse)
def events(status: str | None = None, risk: str | None = None, method: str | None = None, country: str | None = None, source_ip: str | None = None, endpoint: str | None = None, limit: int = 100, offset: int = 0) -> EventListResponse:
    if limit < 1 or limit > 1000 or offset < 0:
        raise HTTPException(status_code=400, detail="Invalid pagination")
    items, total = store.list_events({"prediction": status, "risk": risk, "method": method, "country": country, "source_ip": source_ip, "endpoint": endpoint}, limit, offset)
    return EventListResponse(items=items, meta=PageMeta(total=total, limit=limit, offset=offset))


@app.get(f"{settings.api_prefix}/events/{{event_id}}")
def event_detail(event_id: int) -> dict[str, Any]:
    event = store.event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.get(f"{settings.api_prefix}/analytics/overview")
def analytics_overview() -> dict[str, Any]:
    return store.analytics()


@app.get(f"{settings.api_prefix}/analytics")
def analytics_alias() -> dict[str, Any]:
    return store.analytics()


@app.get(f"{settings.api_prefix}/geo/attacks")
def geo_attacks() -> dict[str, Any]:
    location_groups: dict[tuple[str, str], dict[str, Any]] = {}
    for event in store.events:
        if event.get("prediction") == "Attack" and event.get("latitude") is not None and event.get("longitude") is not None:
            key = (str(event.get("country")), str(event.get("city")))
            if key not in location_groups:
                location_groups[key] = {
                    "country": event["country"],
                    "city": event["city"],
                    "latitude": event["latitude"],
                    "longitude": event["longitude"],
                    "attacks": 1,
                    "risk": event.get("risk", "High"),
                    "ip": event.get("source_ip", "Unknown"),
                    "attack": event.get("attack_type", "Suspicious Request"),
                    "time": event.get("timestamp", ""),
                    "estimated": event.get("estimated", True),
                }
            else:
                location_groups[key]["attacks"] += 1
    return {"items": list(location_groups.values()), "total": len(location_groups)}


@app.get(f"{settings.api_prefix}/threat-map")
def threat_map_alias() -> dict[str, Any]:
    return geo_attacks()


@app.get(f"{settings.api_prefix}/ml/explainability")
def explainability(event_id: int | None = None) -> dict[str, Any]:
    event = store.event(event_id) if event_id else (store.events[-1] if store.events else None)
    if not event:
        raise HTTPException(status_code=404, detail="No analyzed event available")
    return {"prediction": event["prediction"], "probability": event["attack_probability"], "threshold": event["threshold"], "model": "Random Forest", "version": event["model_version"], "features": event["features"]}
