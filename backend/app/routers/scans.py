import os

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.deps import (
    GIT_URL_RE,
    SCAN_JOB_TIMEOUT,
    client_ip,
    get_current_user,
    rate_limit,
    require_auth,
    scan_queue,
)
from shared.db import SessionLocal
from shared.localpath import local_scans_enabled, validate_local_path
from shared.models import Scan, User

# Rate limit: N scan submissions per IP per window (BUILD_PLAN §7).
RATE_LIMIT = int(os.environ.get("SCAN_RATE_LIMIT", "10"))
RATE_WINDOW = int(os.environ.get("SCAN_RATE_WINDOW", "3600"))

router = APIRouter(dependencies=[Depends(require_auth)])


class ScanRequest(BaseModel):
    git_url: str | None = None
    local_path: str | None = None


@router.post("/scans", status_code=202)
def create_scan(
    req: ScanRequest,
    request: Request,
    user: User | None = Depends(get_current_user),
) -> dict:
    rate_limit("scans", client_ip(request), RATE_LIMIT, RATE_WINDOW)
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
        scan = Scan(status="queued", user_id=user.id if user else None, **scan_kwargs)
        session.add(scan)
        session.commit()
        scan_id = scan.id

    # enqueue by dotted name: the worker image owns tasks.py
    scan_queue().enqueue("tasks.run_scan", scan_id, job_timeout=SCAN_JOB_TIMEOUT)
    return {"scan_id": scan_id, "status": "queued"}


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
