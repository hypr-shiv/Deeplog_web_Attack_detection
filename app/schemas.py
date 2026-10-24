from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class AnalystAuthRequest(BaseModel):
    analyst_id: str = Field(min_length=1)
    passcode: str = Field(min_length=1)
    mfa_code: str | None = None
    role: str | None = None


class AuthUserResponse(BaseModel):
    authenticated: bool
    user: dict[str, Any] | None = None
    token: str | None = None
    message: str | None = None


class PredictionResponse(BaseModel):
    prediction: str
    attack_probability: float = Field(ge=0, le=1)
    threshold: float = Field(ge=0, le=1)
    risk: str
    model_version: str


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: int
    timestamp: datetime | str
    source_ip: str
    method: str
    endpoint: str
    prediction: str
    attack_probability: float
    threshold: float
    risk: str
    attack_type: str | None = None
    model_version: str
    country: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    features: dict[str, Any] = Field(default_factory=dict)


class AnalysisSummary(BaseModel):
    id: int | None = None
    file: str
    status: str
    total_requests: int
    normal: int
    attacks: int
    attack_rate: float
    risk_distribution: dict[str, int]
    events: list[SecurityEvent] = Field(default_factory=list)


class PageMeta(BaseModel):
    total: int
    limit: int
    offset: int


class EventListResponse(BaseModel):
    items: list[SecurityEvent]
    meta: PageMeta
