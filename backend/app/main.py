import hmac
import os
import re
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from redis import Redis
from rq import Queue

from shared.db import SessionLocal, init_db
from shared.localpath import local_scans_enabled, validate_local_path
from shared.models import Scan

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# https only; rejects file://, ssh, and anything starting with "-" (option injection)
GIT_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~/-]+(\.git)?$")

SCAN_JOB_TIMEOUT = 3600

# Rate limit: N scan submissions per IP per window (BUILD_PLAN §7).
RATE_LIMIT = int(os.environ.get("SCAN_RATE_LIMIT", "10"))
RATE_WINDOW = int(os.environ.get("SCAN_RATE_WINDOW", "3600"))

_redis = Redis.from_url(REDIS_URL)


def _rate_limit(ip: str) -> None:
    """Fixed-window counter in Redis; raises 429 when exceeded."""
    key = f"ratelimit:scans:{ip}:{int(time.time()) // RATE_WINDOW}"
    count = _redis.incr(key)
    if count == 1:
        _redis.expire(key, RATE_WINDOW)
    if count > RATE_LIMIT:
        raise HTTPException(
            429, f"rate limit exceeded ({RATE_LIMIT} scans per {RATE_WINDOW}s)"
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="VulnScan Code Auditor API", lifespan=lifespan)

# Comma-separated allowed frontend origins (e.g. your Vercel URL in production).
CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get("FRONTEND_ORIGIN", "http://localhost:3000").split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


def scan_queue() -> Queue:
    return Queue("scans", connection=Redis.from_url(REDIS_URL))


# Shared bearer token. When set, all endpoints except /health require it.
# When unset (local dev), auth is disabled. Held server-side only (the Next.js
# proxy on Vercel injects it) so it never reaches the browser.
API_TOKEN = os.environ.get("API_TOKEN", "")


def require_auth(request: Request) -> None:
    if not API_TOKEN:
        return
    header = request.headers.get("authorization", "")
    if not hmac.compare_digest(header, f"Bearer {API_TOKEN}"):
        raise HTTPException(401, "unauthorized")


class ScanRequest(BaseModel):
    git_url: str | None = None
    local_path: str | None = None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scans", status_code=202, dependencies=[Depends(require_auth)])
def create_scan(req: ScanRequest, request: Request) -> dict:
    _rate_limit(request.client.host if request.client else "unknown")
    if bool(req.git_url) == bool(req.local_path):
        raise HTTPException(422, "provide exactly one of git_url or local_path")

    if req.git_url:
        url = req.git_url.strip()
        if not GIT_URL_RE.match(url):
            raise HTTPException(422, "git_url must be a plain https git URL")
        scan_kwargs = {"source_type": "git", "git_url": url}
    else:
        if not local_scans_enabled():
            raise HTTPException(403, "local scans are disabled (set ALLOW_LOCAL_SCANS)")
        try:
            path = validate_local_path(req.local_path)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        scan_kwargs = {"source_type": "local", "local_path": path}

    with SessionLocal() as session:
        scan = Scan(status="queued", **scan_kwargs)
        session.add(scan)
        session.commit()
        scan_id = scan.id

    # enqueue by dotted name: the worker image owns tasks.py
    scan_queue().enqueue("tasks.run_scan", scan_id, job_timeout=SCAN_JOB_TIMEOUT)
    return {"scan_id": scan_id, "status": "queued"}


@app.get("/scans/{scan_id}", dependencies=[Depends(require_auth)])
def get_scan(scan_id: str) -> dict:
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(404, "scan not found")
        return scan.to_dict()
