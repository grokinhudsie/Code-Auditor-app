import os

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import func, select

from app.deps import (
    GIT_URL_RE,
    SCAN_JOB_TIMEOUT,
    client_ip,
    get_current_user,
    rate_limit,
    require_auth,
    require_user,
    scan_queue,
)
from shared.db import SessionLocal
from shared.localpath import local_scans_enabled, validate_local_path
from shared.models import Finding, Scan, User

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


@router.get("/scans")
def list_scans(
    user: User = Depends(require_user), limit: int = 200, offset: int = 0
) -> dict:
    """The logged-in user's scan history (no findings; counts only)."""
    limit = max(1, min(limit, 500))
    with SessionLocal() as session:
        scans = (
            session.query(Scan)
            .filter(Scan.user_id == user.id)
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
                    "target": s.git_url or s.local_path,
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
