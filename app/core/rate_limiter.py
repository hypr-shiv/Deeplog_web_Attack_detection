"""
Production-grade Rate Limiter for DeepLog SIEM.
Provides sliding-window token bucket rate limiting with thread-safe in-memory storage
and optional Redis clustering support.
Defends authentication against brute-force attacks (OWASP A07) and ingestion endpoints
against application-layer DDoS and quota exhaustion.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any
from fastapi import HTTPException, Request, Response, status


class SlidingWindowRateLimiter:
    """Sliding-window token bucket rate limiter with standard RFC 6585 headers."""

    def __init__(self, redis_client: Any | None = None) -> None:
        self.redis = redis_client
        # In-memory sliding window store: key -> deque of timestamp floats
        self._memory_store: dict[str, deque[float]] = defaultdict(deque)

    async def check(
        self,
        key: str,
        max_requests: int = 150,
        window_seconds: int = 60,
        detail: str = "Rate limit exceeded. Request throttled for defense.",
        response: Response | None = None,
    ) -> dict[str, Any]:
        """
        Evaluates the rate limit for the given key in a sliding time window.
        Injects standard X-RateLimit headers into the response if provided.
        Raises HTTP 429 Too Many Requests if quota is exceeded.
        """
        now = time.time()
        clear_before = now - window_seconds

        # Redis distributed cluster check (if configured)
        if self.redis is not None:
            try:
                pipe = self.redis.pipeline()
                pipe.zremrangebyscore(key, 0, clear_before)
                pipe.zcard(key)
                pipe.zadd(key, {f"{now}": now})
                pipe.expire(key, window_seconds)
                _, count, _, _ = await pipe.execute()
                remaining = max(0, max_requests - count)
                reset_seconds = window_seconds

                if response is not None:
                    response.headers["X-RateLimit-Limit"] = str(max_requests)
                    response.headers["X-RateLimit-Remaining"] = str(remaining)
                    response.headers["X-RateLimit-Reset"] = str(reset_seconds)

                if count >= max_requests:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=detail,
                        headers={
                            "Retry-After": str(reset_seconds),
                            "X-RateLimit-Limit": str(max_requests),
                            "X-RateLimit-Remaining": "0",
                            "X-RateLimit-Reset": str(reset_seconds),
                        },
                    )
                return {
                    "allowed": True,
                    "count": count,
                    "remaining": remaining,
                    "reset_seconds": reset_seconds,
                }
            except HTTPException:
                raise
            except Exception:
                pass  # Fall back to in-memory store

        # In-memory sliding window evaluation
        timestamps = self._memory_store[key]
        while timestamps and timestamps[0] < clear_before:
            timestamps.popleft()

        current_count = len(timestamps)
        reset_seconds = (
            max(1, int(timestamps[0] + window_seconds - now))
            if timestamps
            else window_seconds
        )

        if current_count >= max_requests:
            if response is not None:
                response.headers["Retry-After"] = str(reset_seconds)
                response.headers["X-RateLimit-Limit"] = str(max_requests)
                response.headers["X-RateLimit-Remaining"] = "0"
                response.headers["X-RateLimit-Reset"] = str(reset_seconds)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=detail,
                headers={
                    "Retry-After": str(reset_seconds),
                    "X-RateLimit-Limit": str(max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_seconds),
                },
            )

        # Allow and record current timestamp
        timestamps.append(now)
        remaining = max_requests - len(timestamps)

        if response is not None:
            response.headers["X-RateLimit-Limit"] = str(max_requests)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(reset_seconds)

        return {
            "allowed": True,
            "count": len(timestamps),
            "remaining": remaining,
            "reset_seconds": reset_seconds,
        }

    def reset_key(self, key: str) -> None:
        """Clears sliding window timestamps for a given key."""
        if key in self._memory_store:
            self._memory_store[key].clear()

    def get_stats(self) -> dict[str, Any]:
        """Returns statistics on active rate limit tracking keys."""
        return {
            "active_tracked_keys": len(self._memory_store),
            "total_active_entries": sum(len(q) for q in self._memory_store.values()),
        }


rate_limiter = SlidingWindowRateLimiter()


def _get_client_ip(request: Request) -> str:
    """Extracts client IP considering X-Forwarded-For if available."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


async def verify_auth_rate_limit(request: Request, response: Response) -> None:
    """
    Strict rate limit for analyst login/session endpoints:
    Max 10 authentication requests per 60 seconds per IP to defend against brute force
    and credential stuffing attacks (OWASP A07).
    """
    client_ip = _get_client_ip(request)
    key = f"rl:auth:{client_ip}"
    await rate_limiter.check(
        key=key,
        max_requests=10,
        window_seconds=60,
        detail="Too many authentication attempts. Rate limit exceeded (10 attempts/min). Cooldown active for brute-force defense.",
        response=response,
    )


async def verify_upload_rate_limit(request: Request, response: Response) -> None:
    """
    Rate limit for log file uploads:
    Max 10 file uploads per 60 seconds per IP to prevent storage exhaustion and CPU starvation.
    """
    client_ip = _get_client_ip(request)
    key = f"rl:upload:{client_ip}"
    await rate_limiter.check(
        key=key,
        max_requests=10,
        window_seconds=60,
        detail="File upload rate limit exceeded (10 uploads/min). Request throttled for server stability.",
        response=response,
    )


async def verify_ingest_rate_limit(request: Request, response: Response) -> None:
    """
    High-throughput rate limit for live event ingestion:
    Max 250 requests per 60 seconds per IP or API key.
    """
    api_key = request.headers.get("X-DeepLog-Key")
    client_ip = _get_client_ip(request)
    key = f"rl:ingest:{api_key or client_ip}"
    await rate_limiter.check(
        key=key,
        max_requests=250,
        window_seconds=60,
        detail="Ingestion rate limit exceeded (250 events/min). Request throttled for pipeline stability.",
        response=response,
    )


async def verify_api_rate_limit(request: Request, response: Response) -> None:
    """
    General API rate limit for telemetry and historical log queries:
    Max 300 requests per 60 seconds per IP.
    """
    client_ip = _get_client_ip(request)
    key = f"rl:api:{client_ip}"
    await rate_limiter.check(
        key=key,
        max_requests=300,
        window_seconds=60,
        detail="API query rate limit exceeded (300 requests/min).",
        response=response,
    )
