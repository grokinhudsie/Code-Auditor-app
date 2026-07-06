"""Normalize scanner SARIF output into the unified Finding shape (BUILD_PLAN §5)."""

import hashlib
import json
import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

# SARIF level → our severity vocabulary
_LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}

_SCANNER_CATEGORY = {"semgrep": "sast", "gitleaks": "secret"}

# Trivy encodes the finding type in rule tags
_TRIVY_TAG_CATEGORY = {
    "vulnerability": "sca",
    "secret": "secret",
    "misconfiguration": "iac",
    "license": "sca",
}


def finding_id(scanner: str, rule_id: str, file_path: str | None,
               start_line: int | None, snippet: str | None) -> str:
    raw = f"{scanner}|{rule_id}|{file_path}|{start_line}|{snippet}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def redact_secret(snippet: str | None) -> str | None:
    """Hard rule: secrets are never stored or logged in full."""
    if not snippet:
        return snippet
    stripped = snippet.strip()
    if len(stripped) <= 8:
        return "********"
    return f"{stripped[:4]}…[REDACTED]…{stripped[-4:]}"


def _rule_index(run: dict) -> dict:
    rules = {}
    for rule in (run.get("tool", {}).get("driver", {}).get("rules") or []):
        rules[rule.get("id")] = rule
    return rules


def _severity_from_rule(rule: dict, level: str) -> str:
    props = rule.get("properties") or {}
    # security-severity is a CVSS-like 0-10 string used by trivy/semgrep
    score = props.get("security-severity")
    if score:
        try:
            value = float(score)
            if value >= 9.0:
                return "critical"
            if value >= 7.0:
                return "high"
            if value >= 4.0:
                return "medium"
            if value > 0:
                return "low"
        except ValueError:
            pass
    for tag in props.get("tags") or []:
        if tag.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return tag.lower()
    return _LEVEL_SEVERITY.get(level, "medium")


def _category(scanner: str, rule: dict) -> str:
    if scanner in _SCANNER_CATEGORY:
        return _SCANNER_CATEGORY[scanner]
    tags = [t.lower() for t in (rule.get("properties") or {}).get("tags") or []]
    for tag, category in _TRIVY_TAG_CATEGORY.items():
        if tag in tags:
            return category
    return "sast"


def _clean_path(uri: str | None) -> str | None:
    if not uri:
        return None
    for prefix in ("file:///", "file://", "/workspace/repo/", "workspace/repo/", "./"):
        if uri.startswith(prefix):
            uri = uri[len(prefix):]
    return uri or None


def parse_sarif(sarif_text: str, scanner: str) -> list[dict]:
    """Parse one SARIF document into a list of unified finding dicts."""
    sarif = json.loads(sarif_text)
    findings: list[dict] = []

    for run in sarif.get("runs") or []:
        rules = _rule_index(run)
        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or "unknown"
            rule = rules.get(rule_id) or {}
            level = result.get("level") or (rule.get("defaultConfiguration") or {}).get(
                "level", "warning"
            )
            message = (result.get("message") or {}).get("text") or rule_id
            title = (
                (rule.get("shortDescription") or {}).get("text")
                or message.splitlines()[0][:200]
            )

            file_path, start_line, end_line, snippet = None, None, None, None
            locations = result.get("locations") or []
            if locations:
                phys = locations[0].get("physicalLocation") or {}
                file_path = _clean_path(
                    (phys.get("artifactLocation") or {}).get("uri")
                )
                region = phys.get("region") or {}
                start_line = region.get("startLine")
                end_line = region.get("endLine") or start_line
                snippet = (region.get("snippet") or {}).get("text")

            category = _category(scanner, rule)
            if category == "secret":
                snippet = redact_secret(snippet)

            help_text = (rule.get("fullDescription") or {}).get("text") or ""
            help_text += " " + ((rule.get("help") or {}).get("text") or "")
            cve_ids = sorted(set(CVE_RE.findall(f"{rule_id} {title} {message} {help_text}")))

            references = []
            if rule.get("helpUri"):
                references.append(rule["helpUri"])

            findings.append({
                "id": finding_id(scanner, rule_id, file_path, start_line, snippet),
                "scanner": scanner,
                "category": category,
                "rule_id": rule_id,
                "title": title,
                "raw_severity": _severity_from_rule(rule, level),
                "file_path": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "code_snippet": snippet,
                "cve_ids": cve_ids,
                "references": references,
            })

    return findings
