import hmac
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import func, select, update

from app.deps import (
    GIT_URL_RE,
    MAX_UPLOAD_BYTES,
    MAX_UPLOAD_MB,
    PUBLIC_API_BASE,
    SCAN_JOB_TIMEOUT,
    UPLOAD_DIR,
    UPLOAD_TICKET_TTL,
    client_ip,
    get_current_user,
    hash_token,
    rate_limit,
    redis_client,
    require_auth,
    require_user,
    scan_queue,
    zip_uploads_enabled,
)
from shared.db import SessionLocal
from shared.localpath import local_scans_enabled, validate_local_path
from shared.models import Finding, Scan, User

# Rate limit: N scan submissions per IP per window (BUILD_PLAN §7).
RATE_LIMIT = int(os.environ.get("SCAN_RATE_LIMIT", "10"))
RATE_WINDOW = int(os.environ.get("SCAN_RATE_WINDOW", "3600"))

SCAN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
# A zip name is only ever a display/grouping string; it never reaches a path.
UPLOAD_NAME_RE = re.compile(r"^[^\x00-\x1f/\\]{1,200}\.zip$", re.IGNORECASE)

router = APIRouter(dependencies=[Depends(require_auth)])


class ScanRequest(BaseModel):
    git_url: str | None = None
    local_path: str | None = None
    upload_name: str | None = None
    upload_size: int | None = None


@router.post("/scans", status_code=202)
def create_scan(
    req: ScanRequest,
    request: Request,
    user: User | None = Depends(get_current_user),
) -> dict:
    rate_limit("scans", client_ip(request), RATE_LIMIT, RATE_WINDOW)
    _sweep_stale_uploads()
    if sum(map(bool, (req.git_url, req.local_path, req.upload_name))) != 1:
        raise HTTPException(
            422, "provide exactly one of git_url, local_path, or upload_name"
        )

    status = "queued"
    if req.git_url:
        url = req.git_url.strip()
        if not GIT_URL_RE.match(url):
            raise HTTPException(422, "git_url must be a plain https git URL")
        scan_kwargs = {"source_type": "git", "git_url": url}
    elif req.upload_name:
        if not zip_uploads_enabled():
            raise HTTPException(403, "zip uploads are disabled (set PUBLIC_API_BASE)")
        # basename only: the stored name is a label, never a filesystem path
        name = os.path.basename(req.upload_name.strip().replace("\\", "/"))
        if not UPLOAD_NAME_RE.match(name):
            raise HTTPException(422, "upload_name must be a .zip filename")
        if req.upload_size is not None and req.upload_size > MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"upload exceeds the {MAX_UPLOAD_MB}MB cap")
        scan_kwargs = {"source_type": "zip", "upload_name": name}
        # The row is created now so the upload can be bound to it, but nothing is
        # enqueued until the bytes actually land.
        status = "awaiting_upload"
    else:
        if not local_scans_enabled():
            raise HTTPException(403, "local scans are disabled (set ALLOW_LOCAL_SCANS)")
        try:
            path = validate_local_path(req.local_path)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        scan_kwargs = {"source_type": "local", "local_path": path}

    with SessionLocal() as session:
        scan = Scan(status=status, user_id=user.id if user else None, **scan_kwargs)
        session.add(scan)
        session.commit()
        scan_id = scan.id

    if status == "awaiting_upload":
        # One-time ticket, stored hashed like session cookies. This is the only
        # credential the browser gets for the direct-to-droplet upload, and its
        # sole capability is "write <= MAX_UPLOAD_BYTES to this one scan".
        upload_token = secrets.token_urlsafe(32)
        redis_client.setex(
            f"upload:{scan_id}", UPLOAD_TICKET_TTL, hash_token(upload_token)
        )
        return {
            "scan_id": scan_id,
            "status": status,
            "upload_url": f"{PUBLIC_API_BASE}/scans/{scan_id}/upload",
            "upload_token": upload_token,
            "expires_in": UPLOAD_TICKET_TTL,
        }

    # enqueue by dotted name: the worker image owns tasks.py
    scan_queue().enqueue("tasks.run_scan", scan_id, job_timeout=SCAN_JOB_TIMEOUT)
    return {"scan_id": scan_id, "status": "queued"}


@router.get("/scans")
def list_scans(
    user: User = Depends(require_user), limit: int = 200, offset: int = 0
) -> dict:
    """The logged-in user's scan history (no findings; counts only)."""
    limit = max(1, min(limit, 500))
    with SessionLocal() as session:
        scans = (
            session.query(Scan)
            .filter(Scan.user_id == user.id, Scan.status != "awaiting_upload")
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .offset(max(0, offset))
            .all()
        )
        counts = dict(
            session.execute(
                select(Finding.scan_id, func.count())
                .where(Finding.scan_id.in_([s.id for s in scans]))
                .group_by(Finding.scan_id)
            ).all()
        ) if scans else {}
        return {
            "scans": [
                {
                    **s.to_dict(include_findings=False),
                    # never null: the UI uses target as a React/Map key
                    "target": s.git_url or s.local_path or s.upload_name or s.id,
                    "finding_count": counts.get(s.id, 0),
                }
                for s in scans
            ]
        }


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, user: User | None = Depends(get_current_user)) -> dict:
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(404, "scan not found")
        data = scan.to_dict()
        # capability URL: anyone with the link can read; only flag ownership
        data["owned"] = bool(user and scan.user_id == user.id)
        return data


def _sweep_stale_uploads() -> None:
    """Retire tickets that were issued but never used.

    Runs on the (already rate-limited) scan-submit path so there's no scheduler
    to deploy. Rows are cheap to fix; orphaned bytes are what actually costs
    disk, so unlink anything older than two ticket lifetimes.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=2 * UPLOAD_TICKET_TTL)
    try:
        with SessionLocal() as session:
            session.execute(
                update(Scan)
                .where(Scan.status == "awaiting_upload", Scan.created_at < cutoff)
                .values(status="failed", error="upload never completed")
            )
            session.commit()
        if UPLOAD_DIR.is_dir():
            stale = time.time() - 2 * UPLOAD_TICKET_TTL
            for leftover in UPLOAD_DIR.glob("*.zip"):
                if leftover.stat().st_mtime < stale:
                    leftover.unlink(missing_ok=True)
            for partial in UPLOAD_DIR.glob("*.part"):
                if partial.stat().st_mtime < stale:
                    partial.unlink(missing_ok=True)
    except Exception:
        pass  # housekeeping must never fail a scan submission


def _set_scan(scan_id: str, status: str, error: str | None = None) -> None:
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = status
        if error is not None:
            scan.error = error
        session.commit()


# Separate router: the upload arrives straight from the BROWSER, which has no
# API_TOKEN, so it cannot carry the module router's require_auth dependency
# (router-level dependencies can't be waived per-route). The one-time ticket is
# the credential instead.
upload_router = APIRouter()


@upload_router.post("/scans/{scan_id}/upload", status_code=202)
async def upload_zip(scan_id: str, request: Request) -> dict:
    """Receive an uploaded archive and queue the scan.

    Everything is checked BEFORE a single body byte is read, so an unauthorized
    caller can't make us absorb a large body. The bytes are only counted and
    sniffed here, never parsed: interpreting the archive is the sandbox's job.
    """
    if not zip_uploads_enabled() or not SCAN_ID_RE.match(scan_id):
        raise HTTPException(404, "not found")
    # Keyed on scan_id, not IP: behind a reverse proxy client_ip() sees the
    # proxy, and the ticket was already IP-rate-limited when it was issued.
    rate_limit("upload", scan_id, 3, UPLOAD_TICKET_TTL)

    # getdel: single-use and atomic, so two concurrent uploads can't both pass
    stored = redis_client.getdel(f"upload:{scan_id}")
    presented = hash_token(request.headers.get("x-upload-token", ""))
    if stored is None or not hmac.compare_digest(stored.decode(), presented):
        raise HTTPException(401, "invalid or expired upload ticket")

    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"upload exceeds the {MAX_UPLOAD_MB}MB cap")

    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None or scan.source_type != "zip":
            raise HTTPException(404, "not found")
        if scan.status != "awaiting_upload":
            raise HTTPException(409, "this scan already has an upload")

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    partial, final = UPLOAD_DIR / f"{scan_id}.part", UPLOAD_DIR / f"{scan_id}.zip"
    total, magic = 0, b""
    try:
        with open(partial, "wb") as fh:
            async for chunk in request.stream():
                if len(magic) < 4:
                    magic = (magic + chunk)[:4]  # a first chunk can be < 4 bytes
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"upload exceeds the {MAX_UPLOAD_MB}MB cap")
                fh.write(chunk)
        if magic != b"PK\x03\x04":
            raise HTTPException(422, "not a zip archive")
        os.replace(partial, final)
    except BaseException as exc:
        partial.unlink(missing_ok=True)
        detail = exc.detail if isinstance(exc, HTTPException) else "upload failed"
        _set_scan(scan_id, "failed", str(detail))
        raise

    _set_scan(scan_id, "queued")
    scan_queue().enqueue("tasks.run_scan", scan_id, job_timeout=SCAN_JOB_TIMEOUT)
    return {"scan_id": scan_id, "status": "queued"}
