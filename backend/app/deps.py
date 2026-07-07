import hashlib
import hmac
import os
import re
import time
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from redis import Redis
from rq import Queue

from shared.db import SessionLocal
from shared.models import AuthSession, User

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# https only; rejects file://, ssh, and anything starting with "-" (option injection)
GIT_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~/-]+(\.git)?$")

SCAN_JOB_TIMEOUT = 3600

# Comma-separated allowed frontend origins (e.g. your Vercel URL in production).
# The FIRST entry is canonical: it determines the WebAuthn RP ID default and the
# GitHub OAuth callback URL.
CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get("FRONTEND_ORIGIN", "http://localhost:3000").split(",")
    if o.strip()
]

# Shared bearer token. When set, all endpoints except /health require it.
# When unset (local dev), auth is disabled. Held server-side only (the Next.js
# proxy on Vercel injects it) so it never reaches the browser. It authenticates
# the PROXY; user identity rides on top via the session cookie.
API_TOKEN = os.environ.get("API_TOKEN", "")

SESSION_COOKIE = "vs_session"

redis_client = Redis.from_url(REDIS_URL)


def scan_queue() -> Queue:
    return Queue("scans", connection=Redis.from_url(REDIS_URL))


def _proxy_authenticated(request: Request) -> bool:
    header = request.headers.get("authorization", "")
    return bool(API_TOKEN) and hmac.compare_digest(header, f"Bearer {API_TOKEN}")


def require_auth(request: Request) -> None:
    if not API_TOKEN:
        return
    if not _proxy_authenticated(request):
        raise HTTPException(401, "unauthorized")


def client_ip(request: Request) -> str:
    """Real client IP. All production traffic arrives from Vercel's egress IPs,
    so the proxy forwards the browser's IP in X-Client-IP; trust that header
    only when the request proved it came from the proxy (valid API_TOKEN)."""
    if _proxy_authenticated(request):
        forwarded = request.headers.get("x-client-ip", "").strip()
        if forwarded:
            return forwarded
    return request.client.host if request.client else "unknown"


def rate_limit(bucket: str, key: str, limit: int, window: int) -> None:
    """Fixed-window counter in Redis; raises 429 when exceeded."""
    rkey = f"ratelimit:{bucket}:{key}:{int(time.time()) // window}"
    count = redis_client.incr(rkey)
    if count == 1:
        redis_client.expire(rkey, window)
    if count > limit:
        raise HTTPException(429, f"rate limit exceeded ({limit} per {window}s)")


def check_origin(request: Request) -> None:
    """CSRF belt-and-braces on state-changing routes: browsers always send
    Origin on cross-site POSTs, so an Origin outside our allowlist is rejected.
    (Primary defense is the SameSite=Lax session cookie.)"""
    origin = request.headers.get("origin")
    if origin and origin not in CORS_ORIGINS:
        raise HTTPException(403, "origin not allowed")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def get_current_user(request: Request) -> User | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    with SessionLocal() as db:
        session = db.get(AuthSession, hash_token(token))
        if session is None:
            return None
        if session.expires_at < datetime.now(timezone.utc):
            db.delete(session)
            db.commit()
            return None
        return db.get(User, session.user_id)


def require_user(user: User | None = Depends(get_current_user)) -> User:
    if user is None:
        raise HTTPException(401, "login required")
    return user
