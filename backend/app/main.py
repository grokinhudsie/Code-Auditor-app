from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.deps import CORS_ORIGINS, require_auth
from app.routers import auth, projects, scans
from shared.db import init_db
from shared.localpath import local_scans_enabled


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
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
def capabilities() -> dict[str, bool]:
    """Optional features this deployment allows, so the UI only offers what
    the backend will actually accept. Token-gated: config, not public info."""
    return {"local_scans": local_scans_enabled()}


app.include_router(scans.router)
app.include_router(auth.router)
app.include_router(projects.router)
