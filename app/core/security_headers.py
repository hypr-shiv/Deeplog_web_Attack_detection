"""
Security Headers Middleware for DeepLog SIEM.
Enforces OWASP Top 10 defenses: HSTS, Anti-Clickjacking, Anti-MIME Sniffing, and Strict CSP.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        # 1. Enforce HSTS (2 years, including subdomains, preloaded)
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )

        # 2. Prevent clickjacking (Anti-Framing)
        response.headers["X-Frame-Options"] = "DENY"

        # 3. Block MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # 4. Strict Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 5. Disable unused browser capabilities
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=(), display-capture=()"
        )

        # 6. Strict Content Security Policy (allows MapLibre WebWorkers and WebSockets)
        csp = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https://*.tile.openstreetmap.org https://basemaps.cartocdn.com; "
            "connect-src 'self' ws://127.0.0.1:8000 ws://localhost:8000 ws://127.0.0.1:5173 ws://localhost:5173 ws://127.0.0.1:* ws://localhost:* wss://* http://127.0.0.1:8000 http://localhost:8000 http://127.0.0.1:5173 http://localhost:5173; "
            "worker-src 'self' blob:; "
            "child-src 'self' blob:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers["Content-Security-Policy"] = csp

        return response
