from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.deps import (
    CORS_ORIGINS,
    MAX_UPLOAD_MB,
    UPLOAD_DIR,
    require_auth,
    zip_uploads_enabled,
)
from app.routers import auth, projects, scans
from shared.db import init_db
from shared.localpath import local_scans_enabled


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if zip_uploads_enabled():
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title="VulnScan Code Auditor API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/capabilities", dependencies=[Depends(require_auth)])
def capabilities() -> dict:
    """Optional features this deployment allows, so the UI only offers what
    the backend will actually accept. Token-gated: config, not public info."""
    return {
        "local_scans": local_scans_enabled(),
        "zip_uploads": zip_uploads_enabled(),
        "max_upload_mb": MAX_UPLOAD_MB,
    }


app.include_router(scans.router)
app.include_router(scans.upload_router)
app.include_router(auth.router)
app.include_router(projects.router)
