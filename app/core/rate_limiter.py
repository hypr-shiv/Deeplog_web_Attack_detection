"""
Production-grade Rate Limiter for DeepLog SIEM.
Provides sliding-window token bucket rate limiting with Redis and thread-safe in-memory fallback.
Defends ingestion endpoints against application-layer DDoS and quota exhaustion.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any
from fastapi import HTTPException, Request, status


class SlidingWindowRateLimiter:
    """Sliding-window token bucket rate limiter."""

    def __init__(self, redis_client: Any | None = None) -> None:
        self.redis = redis_client
        # In-memory sliding window fallback: key -> deque of timestamps
        self._memory_store: dict[str, deque[float]] = defaultdict(deque)

    async def check(
        self,
        key: str,
        max_requests: int = 150,
        window_seconds: int = 60,
    ) -> None:
        now = time.time()
        clear_before = now - window_seconds

        # Use Redis if active
        if self.redis is not None:
            try:
                pipe = self.redis.pipeline()
                pipe.zremrangebyscore(key, 0, clear_before)
                pipe.zcard(key)
                pipe.zadd(key, {f"{now}": now})
                pipe.expire(key, window_seconds)
                _, count, _, _ = await pipe.execute()
                if count >= max_requests:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Rate limit exceeded. Ingestion request throttled for defense.",
                        headers={"Retry-After": str(window_seconds)},
                    )
                return
            except Exception:
                pass  # Fall back to in-memory store

        # In-memory sliding window evaluation
        timestamps = self._memory_store[key]
        while timestamps and timestamps[0] < clear_before:
            timestamps.popleft()

        if len(timestamps) >= max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Ingestion request throttled for defense.",
                headers={"Retry-After": str(window_seconds)},
            )

        timestamps.append(now)


rate_limiter = SlidingWindowRateLimiter()


async def verify_ingest_rate_limit(request: Request) -> None:
    """FastAPI dependency to rate limit by IP or API Key."""
    api_key = request.headers.get("X-DeepLog-Key")
    client_ip = request.client.host if request.client else "127.0.0.1"
    key = f"rl:ingest:{api_key or client_ip}"

    # Allow 250 requests per minute per IP / key
    await rate_limiter.check(key, max_requests=250, window_seconds=60)
