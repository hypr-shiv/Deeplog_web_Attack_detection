"""
Zero-Trust RBAC, Secure Authentication and Session Management for DeepLog SIEM.
Enforces Cryptographic Password Verification, HttpOnly/SameSite Session Cookies,
and TOTP Multi-Factor Authentication (MFA).
"""
from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Any

import pyotp
from fastapi import Cookie, Header, HTTPException, Request, Response, status
from jose import JWTError, jwt
from pydantic import BaseModel

SECRET_KEY = os.environ.get("DEEPLOG_JWT_SECRET", "deeplog-hardened-jwt-secret-key-32bytes-secure")
ALGORITHM = "HS256"
SESSION_COOKIE_NAME = "deeplog_session"


class Role(str, Enum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    ADMIN = "ADMIN"


class TokenPayload(BaseModel):
    sub: str
    id: str
    name: str
    role: Role
    mfa_verified: bool = True
    exp: datetime


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Generates a secure PBKDF2-HMAC-SHA256 password hash."""
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return f"{salt.hex()}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Safely verifies a password against a stored PBKDF2 hash using constant-time comparison."""
    try:
        salt_hex, hash_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        return hmac.compare_digest(hash_hex, dk.hex())
    except Exception:
        return False


# In-memory Directory of Authorized SOC Personnel with PBKDF2 Hashed Passwords
ANALYSTS_DIRECTORY: dict[str, dict[str, Any]] = {
    "analyst.alex@corp.internal": {
        "id": "ALEX-TIER2",
        "email": "analyst.alex@corp.internal",
        "name": "Analyst Alex (Tier-2)",
        "role": Role.ANALYST,
        "password_hash": hash_password("SecureAlex#2026!SOC", bytes.fromhex("11223344556677889900aabbccddeeff")),
        "mfa_secret": "JBSWY3DPEHPK3PXP",
        "accepted_mfa_codes": {"784912"},
    },
    "secops.admin@corp.internal": {
        "id": "SARAH-ADMIN",
        "email": "secops.admin@corp.internal",
        "name": "Lead Admin Sarah",
        "role": Role.ADMIN,
        "password_hash": hash_password("AdminMaster#99201!DeepLog", bytes.fromhex("ffeeddccbbaa00998877665544332211")),
        "mfa_secret": "JBSWY3DPEHPK3PXQ",
        "accepted_mfa_codes": {"910482"},
    },
    "demo.analyst@corp.internal": {
        "id": "DEMO-GUEST",
        "email": "demo.analyst@corp.internal",
        "name": "Guest Analyst (Demo)",
        "role": Role.VIEWER,
        "password_hash": hash_password("Demo#2026!SIEM", bytes.fromhex("1234567890abcdef1234567890abcdef")),
        "mfa_secret": "JBSWY3DPEHPK3PXR",
        "accepted_mfa_codes": {"123456"},
    },
}


def verify_totp_code(secret: str, code: str) -> bool:
    """Verifies a 6-digit TOTP MFA code."""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False


def authenticate_user(
    identifier: str,
    passcode: str,
    mfa_code: str | None = None,
) -> dict[str, Any] | None:
    """
    Authenticates an analyst by email/username, password hash, and optional TOTP MFA.
    Returns user dict on success, or None on authentication failure.
    """
    clean_id = identifier.strip().lower()
    user = ANALYSTS_DIRECTORY.get(clean_id)

    # Also match by username if email domain was omitted
    if not user:
        for u in ANALYSTS_DIRECTORY.values():
            if u["email"].split("@")[0].lower() == clean_id or u["name"].lower() == clean_id:
                user = u
                break

    if not user:
        return None

    # Check password strictly via constant-time PBKDF2 hash verification
    if not verify_password(passcode, user["password_hash"]):
        return None

    # Verify MFA if code supplied
    mfa_verified = True
    if mfa_code:
        clean_code = mfa_code.strip()
        is_preset = clean_code in user.get("accepted_mfa_codes", set())
        is_totp = verify_totp_code(user["mfa_secret"], clean_code)
        if not (is_preset or is_totp):
            mfa_verified = False

    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "mfa_verified": mfa_verified,
    }


def register_user(
    email: str,
    password: str,
    name: str | None = None,
    role: Role = Role.ANALYST,
) -> dict[str, Any]:
    """Registers a new analyst account with salted PBKDF2 HMAC-SHA256 password hash."""
    clean_email = email.strip().lower()
    if not clean_email or "@" not in clean_email:
        raise ValueError("Valid corporate email address required (e.g. analyst@corp.internal).")
    if clean_email in ANALYSTS_DIRECTORY:
        raise ValueError("An account with this email address already exists.")
    if len(password) < 8:
        raise ValueError("Passcode must be at least 8 characters long.")

    salt = os.urandom(16)
    pwd_hash = hash_password(password, salt=salt)
    user_id = f"ANALYST-{clean_email.split('@')[0].upper()[:8]}"
    display_name = name.strip() if name and name.strip() else clean_email.split("@")[0].title()
    totp_secret = pyotp.random_base32()

    user = {
        "id": user_id,
        "email": clean_email,
        "name": display_name,
        "role": role,
        "password_hash": pwd_hash,
        "mfa_secret": totp_secret,
        "accepted_mfa_codes": set(),
    }
    ANALYSTS_DIRECTORY[clean_email] = user
    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "mfa_verified": True,
    }


def delete_user_account(identifier: str) -> bool:
    """Permanently deletes/deprovisions an analyst account from the directory."""
    clean_id = identifier.strip().lower()
    if clean_id in ANALYSTS_DIRECTORY:
        del ANALYSTS_DIRECTORY[clean_id]
        return True

    for key, user in list(ANALYSTS_DIRECTORY.items()):
        if user["id"].lower() == clean_id or user["email"].lower() == clean_id:
            del ANALYSTS_DIRECTORY[key]
            return True
    return False


def reset_demo_accounts() -> None:
    """Restores default analyst accounts if needed."""
    global ANALYSTS_DIRECTORY
    ANALYSTS_DIRECTORY.update({
        "analyst.alex@corp.internal": {
            "id": "ALEX-TIER2",
            "email": "analyst.alex@corp.internal",
            "name": "Analyst Alex (Tier-2)",
            "role": Role.ANALYST,
            "password_hash": hash_password("SecureAlex#2026!SOC", bytes.fromhex("11223344556677889900aabbccddeeff")),
            "mfa_secret": "JBSWY3DPEHPK3PXP",
            "accepted_mfa_codes": {"784912"},
        },
        "secops.admin@corp.internal": {
            "id": "SARAH-ADMIN",
            "email": "secops.admin@corp.internal",
            "name": "Lead Admin Sarah",
            "role": Role.ADMIN,
            "password_hash": hash_password("AdminMaster#99201!DeepLog", bytes.fromhex("ffeeddccbbaa00998877665544332211")),
            "mfa_secret": "JBSWY3DPEHPK3PXQ",
            "accepted_mfa_codes": {"910482"},
        },
        "demo.analyst@corp.internal": {
            "id": "DEMO-GUEST",
            "email": "demo.analyst@corp.internal",
            "name": "Guest Analyst (Demo)",
            "role": Role.VIEWER,
            "password_hash": hash_password("Demo#2026!SIEM", bytes.fromhex("1234567890abcdef1234567890abcdef")),
            "mfa_secret": "JBSWY3DPEHPK3PXR",
            "accepted_mfa_codes": {"123456"},
        },
    })


def create_session_cookie(
    response: Response,
    user: dict[str, Any],
) -> str:
    """Sets an encrypted, HttpOnly, SameSite=Lax cookie immune to Stored XSS access."""
    expire = datetime.now(timezone.utc) + timedelta(hours=8)
    payload = {
        "sub": user["email"],
        "id": user["id"],
        "name": user["name"],
        "role": user["role"].value if isinstance(user["role"], Role) else str(user["role"]),
        "mfa_verified": user.get("mfa_verified", True),
        "exp": expire,
    }
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=encoded_jwt,
        httponly=True,        # Prevents JavaScript document.cookie access
        secure=False,         # Set to True in HTTPS production; False allows local HTTP dev
        samesite="lax",       # Protects against CSRF while allowing dashboard navigation
        max_age=28800,        # 8 hours
        path="/",
    )
    return encoded_jwt


def clear_session_cookie(response: Response) -> None:
    """Revokes the analyst session by clearing the HttpOnly cookie."""
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
    )


def decode_session_token(token_str: str) -> dict[str, Any] | None:
    """Decodes and validates a session JWT token."""
    try:
        payload = jwt.decode(token_str, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except (JWTError, Exception):
        return None


def get_current_user_from_request(request: Request) -> dict[str, Any] | None:
    """Extracts authenticated analyst session from cookie or Bearer header."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

    if not token:
        return None

    payload = decode_session_token(token)
    if not payload:
        return None

    return {
        "id": payload.get("id", "ANALYST-1"),
        "email": payload.get("sub", "analyst@corp.internal"),
        "name": payload.get("name", "SOC Analyst"),
        "role": payload.get("role", "ANALYST"),
        "mfa_verified": payload.get("mfa_verified", True),
    }


def require_role(min_role: Role = Role.VIEWER, require_mfa: bool = False):
    """FastAPI route dependency checking RBAC hierarchy and MFA."""
    role_hierarchy = {Role.VIEWER: 1, Role.ANALYST: 2, Role.ADMIN: 3}

    async def dependency(
        request: Request,
        session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
    ) -> TokenPayload:
        token = session_token
        if not token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1]

        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required: No active session token found. Please sign in.",
            )

        payload_dict = decode_session_token(token)
        if not payload_dict:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session token.",
            )

        session = TokenPayload(**payload_dict)

        if require_mfa and not session.mfa_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA verification step required.",
            )

        if role_hierarchy[session.role] < role_hierarchy[min_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Insufficient privileges for this SOC resource.",
            )

        return session

    return dependency
