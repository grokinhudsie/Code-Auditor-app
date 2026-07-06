import os
import re
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from redis import Redis
from rq import Queue

from shared.db import SessionLocal, init_db
from shared.models import Scan

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# https only; rejects file://, ssh, and anything starting with "-" (option injection)
GIT_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~/-]+(\.git)?$")

SCAN_JOB_TIMEOUT = 3600


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="VulnScanner API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def scan_queue() -> Queue:
    return Queue("scans", connection=Redis.from_url(REDIS_URL))


class ScanRequest(BaseModel):
    git_url: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scans", status_code=202)
def create_scan(req: ScanRequest) -> dict:
    url = req.git_url.strip()
    if not GIT_URL_RE.match(url):
        raise HTTPException(422, "git_url must be a plain https git URL")

    with SessionLocal() as session:
        scan = Scan(git_url=url, status="queued")
        session.add(scan)
        session.commit()
        scan_id = scan.id

    # enqueue by dotted name: the worker image owns tasks.py
    scan_queue().enqueue("tasks.run_scan", scan_id, job_timeout=SCAN_JOB_TIMEOUT)
    return {"scan_id": scan_id, "status": "queued"}


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(404, "scan not found")
        return scan.to_dict()
