"""Scan pipeline executed by the RQ worker."""

import re

from shared.db import SessionLocal, init_db
from shared.models import Finding, Scan
from shared.normalize import parse_sarif

import sandbox
import scanners

GIT_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~/-]+(\.git)?$")


def _set_status(scan_id: str, status: str, **fields) -> None:
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = status
        for key, value in fields.items():
            setattr(scan, key, value)
        session.commit()


def _store_findings(scan_id: str, findings: list[dict]) -> None:
    with SessionLocal() as session:
        session.query(Finding).filter_by(scan_id=scan_id).delete()
        seen: set[str] = set()
        for f in findings:
            if f["id"] in seen:  # identical finding reported twice in one run
                continue
            seen.add(f["id"])
            session.add(Finding(scan_id=scan_id, **f))
        session.commit()


def run_scan(scan_id: str) -> None:
    init_db()
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise RuntimeError(f"scan {scan_id} not found")
        git_url = scan.git_url

    if not GIT_URL_RE.match(git_url):
        _set_status(scan_id, "failed", error="invalid git URL")
        return

    volume = None
    try:
        _set_status(scan_id, "cloning")
        volume = sandbox.create_workspace(scan_id)
        sandbox.clone_repo(volume, git_url)
        tree = sandbox.list_file_tree(volume)
        _set_status(scan_id, "scanning", file_tree=tree)

        findings: list[dict] = []
        semgrep_sarif = scanners.run_semgrep(volume)
        findings += parse_sarif(semgrep_sarif, "semgrep")

        _store_findings(scan_id, findings)
        _set_status(scan_id, "completed")
    except Exception as exc:
        _set_status(scan_id, "failed", error=str(exc)[:4000])
        raise
    finally:
        if volume:
            sandbox.remove_workspace(volume)
