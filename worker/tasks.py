"""Scan pipeline executed by the RQ worker."""

import re

from shared.db import SessionLocal, init_db
from shared.localpath import local_scans_enabled, validate_local_path
from shared.models import Finding, Scan
from shared.normalize import dedupe, parse_sarif
from shared import llm

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


def _gather_contexts(volume: str, findings: list[dict]) -> dict[str, str]:
    ctx: dict[str, str] = {}
    for f in findings:
        if f.get("file_path") and f.get("start_line"):
            src = sandbox.read_source(
                volume, f["file_path"], f["start_line"], f.get("end_line") or f["start_line"]
            )
            if src:
                ctx[f["id"]] = src
    return ctx


def _triage(scan_id: str, findings: list[dict], contexts: dict, errors: list) -> None:
    _set_status(scan_id, "triaging")
    try:
        verdicts = llm.triage(findings, contexts)
    except Exception as exc:
        errors.append(f"triage: {str(exc)[:500]}")
        return
    with SessionLocal() as session:
        for f in findings:
            v = verdicts.get(f["id"])
            if not v:
                continue
            row = session.get(Finding, (f["id"], scan_id))
            if row:
                row.triaged_severity = v["triaged_severity"]
                row.likely_false_positive = v["likely_false_positive"]
                row.explanation = v["explanation"]
                f["likely_false_positive"] = v["likely_false_positive"]  # for patch filter
        session.commit()


def _patch(scan_id: str, volume: str, findings: list[dict], contexts: dict,
           errors: list) -> None:
    _set_status(scan_id, "patching")
    for f in findings:
        if f.get("likely_false_positive"):  # skip likely FPs (BUILD_PLAN §5)
            continue
        try:
            result = llm.generate_patch(f, contexts.get(f["id"]))
        except Exception as exc:
            errors.append(f"patch {f['id'][:8]}: {str(exc)[:200]}")
            continue
        patch = result.get("patch")
        if patch and not sandbox.check_patch_applies(volume, patch):
            # Present only patches we verified apply cleanly.
            patch = None
        with SessionLocal() as session:
            row = session.get(Finding, (f["id"], scan_id))
            if row:
                row.suggested_patch = patch
                row.patch_rationale = result.get("rationale")
                session.commit()


def run_scan(scan_id: str) -> None:
    init_db()
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise RuntimeError(f"scan {scan_id} not found")
        source_type = scan.source_type or "git"
        git_url = scan.git_url
        local_path = scan.local_path

    # Re-validate the source here too (defense in depth vs a tampered DB row).
    if source_type == "local":
        if not local_scans_enabled():
            _set_status(scan_id, "failed", error="local scans are disabled on this worker")
            return
        try:
            local_path = validate_local_path(local_path or "")
        except ValueError as exc:
            _set_status(scan_id, "failed", error=f"invalid local path: {exc}")
            return
    elif not (git_url and GIT_URL_RE.match(git_url)):
        _set_status(scan_id, "failed", error="invalid git URL")
        return

    volume = None
    errors: list[str] = []
    try:
        if source_type == "local":
            _set_status(scan_id, "copying")
            volume = sandbox.create_workspace(scan_id)
            sandbox.copy_local_dir(volume, local_path)
        else:
            _set_status(scan_id, "cloning")
            volume = sandbox.create_workspace(scan_id)
            sandbox.clone_repo(volume, git_url)
        git_mode = sandbox.has_git_dir(volume)
        tree = sandbox.list_file_tree(volume)
        _set_status(scan_id, "scanning", file_tree=tree)

        findings: list[dict] = []
        # Each scanner is isolated: a failure in one shouldn't lose the others.
        for name, runner in (
            ("semgrep", scanners.run_semgrep),
            ("trivy", scanners.run_trivy),
            ("gitleaks", lambda v: scanners.run_gitleaks(v, git_mode=git_mode)),
        ):
            try:
                sarif = runner(volume)
                findings += parse_sarif(sarif, name)
            except Exception as exc:
                errors.append(f"{name}: {str(exc)[:500]}")

        findings = dedupe(findings)
        _store_findings(scan_id, findings)

        if llm.available() and findings:
            contexts = _gather_contexts(volume, findings)
            _triage(scan_id, findings, contexts, errors)
            _patch(scan_id, volume, findings, contexts, errors)

        _set_status(
            scan_id,
            "completed",
            error="; ".join(errors) if errors else None,
        )
    except Exception as exc:
        _set_status(scan_id, "failed", error=str(exc)[:4000])
        raise
    finally:
        if volume:
            sandbox.remove_workspace(volume)
