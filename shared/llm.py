"""LLM triage + patch generation via the Anthropic API.

Both calls are structured via tool use so the model returns validated JSON, not
prose. If no ANTHROPIC_API_KEY is configured, `available()` is False and the
worker skips the LLM stages (findings are still stored, just un-triaged).

Triage and patch generation are separate calls (BUILD_PLAN §7) and prompts live
in versioned files under backend/prompts/, mounted into the worker image.
"""

import json
import os
from functools import lru_cache
from pathlib import Path

MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-fable-5")
PROMPT_DIR = Path(os.environ.get("PROMPT_DIR", "/app/prompts"))
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
CACHE_TTL = int(os.environ.get("TRIAGE_CACHE_TTL", str(30 * 24 * 3600)))

# Fable 5 / Mythos 5 have thinking always on (forced tool_choice is rejected) and
# run safety classifiers that can false-positive-refuse security-triage content.
# For those models we use auto tool_choice and a server-side fallback to a GA
# model. Set ANTHROPIC_FALLBACK_MODEL="" to disable the fallback.
FALLBACK_MODEL = os.environ.get("ANTHROPIC_FALLBACK_MODEL", "claude-opus-4-8")
_THINKING_ALWAYS_ON = MODEL.startswith(("claude-fable-5", "claude-mythos-5"))
MAX_TOKENS = int(os.environ.get("ANTHROPIC_MAX_TOKENS", "8192"))

_TRIAGE_BATCH = 8


@lru_cache(maxsize=1)
def _cache():
    """Redis handle for triage caching (BUILD_PLAN §7). Cache is keyed by the
    finding's content hash, so identical findings across scans reuse the verdict
    and don't re-spend LLM tokens."""
    try:
        from redis import Redis

        r = Redis.from_url(REDIS_URL)
        r.ping()
        return r
    except Exception:
        return None


def _cache_get(finding_id: str) -> dict | None:
    r = _cache()
    if not r:
        return None
    raw = r.get(f"triage:{MODEL}:{finding_id}")
    return json.loads(raw) if raw else None


def _cache_set(finding_id: str, verdict: dict) -> None:
    r = _cache()
    if r:
        r.setex(f"triage:{MODEL}:{finding_id}", CACHE_TTL, json.dumps(verdict))


def available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


@lru_cache(maxsize=None)
def _prompt(name: str) -> str:
    return (PROMPT_DIR / name).read_text()


@lru_cache(maxsize=1)
def _client():
    import anthropic

    return anthropic.Anthropic()


TRIAGE_TOOL = {
    "name": "record_triage",
    "description": "Record the triage verdict for each finding.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdicts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "triaged_severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                        "likely_false_positive": {"type": "boolean"},
                        "explanation": {"type": "string"},
                    },
                    "required": [
                        "id",
                        "triaged_severity",
                        "likely_false_positive",
                        "explanation",
                    ],
                },
            }
        },
        "required": ["verdicts"],
    },
}

PATCH_TOOL = {
    "name": "record_patch",
    "description": "Record a suggested fix as a unified diff plus rationale.",
    "input_schema": {
        "type": "object",
        "properties": {
            "patch": {
                "type": "string",
                "description": "Unified diff, or empty string if no safe patch.",
            },
            "rationale": {"type": "string"},
        },
        "required": ["patch", "rationale"],
    },
}


def _finding_block(f: dict, context: str | None) -> str:
    meta = {
        "id": f["id"],
        "scanner": f["scanner"],
        "category": f["category"],
        "rule_id": f["rule_id"],
        "title": f["title"],
        "raw_severity": f["raw_severity"],
        "file_path": f["file_path"],
        "start_line": f["start_line"],
        "end_line": f["end_line"],
        "cve_ids": f["cve_ids"],
        "references": f["references"][:5],
    }
    parts = ["FINDING:", json.dumps(meta, indent=2)]
    if f.get("code_snippet"):
        parts += ["FLAGGED SNIPPET:", f["code_snippet"]]
    if context:
        parts += ["SURROUNDING CODE:", context]
    return "\n".join(parts)


def _tool_input(response, tool_name: str) -> dict | None:
    for block in response.content:
        if block.type == "tool_use" and block.name == tool_name:
            return block.input
    return None


def _invoke(system: str, tool: dict, tool_name: str, user: str) -> dict:
    """One structured LLM call. Returns the tool input dict, or {} if the model
    refused or didn't call the tool."""
    kwargs = dict(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=system,
        tools=[tool],
        # Thinking-always-on models reject forced tool_choice; auto + a
        # "respond only via the tool" system prompt is the compatible path.
        tool_choice={"type": "auto"} if _THINKING_ALWAYS_ON
        else {"type": "tool", "name": tool_name},
        messages=[{"role": "user", "content": user}],
    )
    if _THINKING_ALWAYS_ON and FALLBACK_MODEL and FALLBACK_MODEL != MODEL:
        try:
            resp = _client().beta.messages.create(
                betas=["server-side-fallback-2026-06-01"],
                fallbacks=[{"model": FALLBACK_MODEL}],
                **kwargs,
            )
        except Exception:
            # Fallback beta not enabled on this account — degrade to a plain call.
            resp = _client().messages.create(**kwargs)
    else:
        resp = _client().messages.create(**kwargs)

    if getattr(resp, "stop_reason", None) == "refusal":
        return {}
    return _tool_input(resp, tool_name) or {}


def triage(findings: list[dict], contexts: dict[str, str]) -> dict[str, dict]:
    """Return {finding_id: {triaged_severity, likely_false_positive, explanation}}."""
    results: dict[str, dict] = {}

    # Serve cache hits first; only send cache misses to the model.
    pending = []
    for f in findings:
        cached = _cache_get(f["id"])
        if cached is not None:
            results[f["id"]] = cached
        else:
            pending.append(f)

    for i in range(0, len(pending), _TRIAGE_BATCH):
        batch = pending[i : i + _TRIAGE_BATCH]
        blocks = "\n\n---\n\n".join(
            _finding_block(f, contexts.get(f["id"])) for f in batch
        )
        user = (
            f"Triage the following {len(batch)} finding(s). Return one verdict per "
            f"finding, keyed by the exact `id` shown.\n\n{blocks}"
        )
        data = _invoke(_prompt("triage_system.txt"), TRIAGE_TOOL, "record_triage", user)
        for v in data.get("verdicts", []):
            if v.get("id"):
                verdict = {
                    "triaged_severity": v.get("triaged_severity"),
                    "likely_false_positive": v.get("likely_false_positive"),
                    "explanation": v.get("explanation"),
                }
                results[v["id"]] = verdict
                _cache_set(v["id"], verdict)
    return results


def generate_patch(finding: dict, context: str | None) -> dict:
    """Return {patch, rationale} for one finding."""
    user = (
        "Write a fix for the following finding.\n\n"
        + _finding_block(finding, context)
    )
    data = _invoke(_prompt("patch_system.txt"), PATCH_TOOL, "record_patch", user)
    return {
        "patch": data.get("patch") or None,
        "rationale": data.get("rationale") or None,
    }
