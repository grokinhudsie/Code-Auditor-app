# VulnScanner — Build Plan

A web app that ingests a website codebase, runs it through best-in-class open-source
security scanners, and uses an LLM to triage findings and suggest patches.

> **Working note for Claude Code:** Build this in the numbered phases below, in order.
> Each phase ends with a **Definition of Done** and a manual verification step. Do not
> start a phase until the previous one's checks pass. Commit at the end of each phase.
> Ask me before introducing any dependency not listed here.

---

## 1. Scope & philosophy

- **We do not write our own vulnerability detection.** We orchestrate mature scanners and
  add a triage + remediation layer on top. That layer is the product.
- **Detection categories:**
  - SCA (known CVEs in dependencies) — the highest-value category.
  - SAST (vulnerable patterns in our code: injection, XSS, SSRF, path traversal, etc.).
  - Secret scanning (leaked keys/credentials).
  - IaC/config misconfiguration (Docker, Terraform, k8s).
- **"Latest exploits" is handled by keeping scanner databases fresh**, not by hand-coding
  signatures. Refresh DBs on every run.
- **Honest limitation to bake into the UX:** no tool finds "every vulnerability." The real
  job is prioritization and low false-positive triage. Design around that, not exhaustiveness.

---

## 2. Tech stack (fixed — don't substitute without asking)

| Layer | Choice | Why |
|---|---|---|
| Backend API | Python 3.12 + FastAPI | Security tooling ecosystem is Python-native; easy SARIF handling |
| Async jobs | Redis + RQ | Scans are long-running; keep API responsive. (Celery is overkill for MVP) |
| DB | PostgreSQL + SQLAlchemy | Structured findings, scan history |
| Scanners | Trivy, Semgrep, Gitleaks | See §4 |
| LLM | Anthropic API (Claude) | Triage + patch generation |
| Frontend | Next.js (React) + Tailwind | Standard, fast to build |
| Sandbox | Docker (ephemeral containers per scan) | Input is untrusted code — isolation is mandatory |

---

## 3. Architecture

```
[Next.js UI] → POST git URL / upload
      │
      ▼
[FastAPI] → enqueue scan job (RQ) → returns job_id
      │
      ▼
[Worker] ── clones repo into ephemeral sandbox container ──┐
      │                                                     │
      │   runs each scanner inside the sandbox:             │
      │     Trivy (SCA + secrets + IaC)                     │
      │     Semgrep (SAST)                                  │
      │     Gitleaks (secrets, second opinion)              │
      │                                                     │
      ▼                                                     │
[Normalizer] → parse SARIF → unified Finding schema → dedupe┘
      │
      ▼
[LLM Triage] → severity re-rank, false-positive filter, plain-English explanation
      │
      ▼
[LLM Patch Gen] → per finding, produce a suggested diff + rationale
      │
      ▼
[Postgres] ← persist Scan + Findings
      │
      ▼
[UI] ← poll job status → render grouped, prioritized findings with diffs
```

---

## 4. Scanners (MVP set)

Start with these three. All are single binaries or pip-installable and emit machine-readable output.

- **Trivy** — does SCA, secret scanning, and IaC in one tool. Highest coverage-per-effort.
  Emits SARIF. Refresh its vuln DB before each scan (`trivy --download-db-only`).
- **Semgrep** — SAST. Use the free community ruleset (`--config auto` or `p/default`).
  Emits SARIF. Pull latest rules per run.
- **Gitleaks** — dedicated secret scanner as a second opinion. Emits SARIF/JSON.

**Defer to later:** OSV-Scanner, CodeQL (powerful but heavier setup), Checkov.

---

## 5. Unified Finding schema

Every scanner's output normalizes into this shape. This is the contract the whole app uses.

```python
class Finding(BaseModel):
    id: str                  # stable hash: scanner + rule_id + file + line + snippet
    scanner: str             # "trivy" | "semgrep" | "gitleaks"
    category: str            # "sca" | "sast" | "secret" | "iac"
    rule_id: str             # native rule/CVE id, e.g. "CVE-2024-1234"
    title: str
    raw_severity: str        # as reported by scanner
    file_path: str | None
    start_line: int | None
    end_line: int | None
    code_snippet: str | None
    cve_ids: list[str]       # for SCA findings
    references: list[str]    # advisory URLs

    # filled in by the LLM layer:
    triaged_severity: str | None = None   # critical|high|medium|low|info
    likely_false_positive: bool | None = None
    explanation: str | None = None        # plain-English, in context of THIS code
    suggested_patch: str | None = None    # unified diff
    patch_rationale: str | None = None
```

SARIF maps cleanly onto this. Dedupe across scanners by `(file_path, start_line, rule_id)`
and by overlapping CVE ids.

---

## 6. Build phases

### Phase 0 — Scaffold
- Monorepo: `/backend` (FastAPI), `/frontend` (Next.js), `/worker`, `docker-compose.yml`.
- `docker-compose` brings up: api, worker, redis, postgres.
- Health-check endpoint `GET /health`.
- **DoD:** `docker compose up` runs all four services; `/health` returns 200.

### Phase 1 — Ingestion (sandboxed)
- Endpoint `POST /scans` accepts a git URL (and later, a zip upload). Returns `job_id`.
- Worker clones the repo into a **fresh, network-restricted, non-root container** with a
  CPU/memory/time limit. Never run scanners on the host or in the worker container itself.
- **DoD:** submitting a public repo URL clones it into an isolated container and reports
  the file tree back. Verify the sandbox cannot reach the host or the internet beyond the clone.

### Phase 2 — First scanner end-to-end (Semgrep)
- Run Semgrep in the sandbox, capture SARIF, parse it into `Finding` objects, store in Postgres.
- **DoD:** scanning a deliberately vulnerable test repo (use `OWASP/NodeGoat` or
  `dvwa`-style sample) returns parsed findings via `GET /scans/{id}`.

### Phase 3 — Add scanners + normalize + dedupe
- Add Trivy and Gitleaks. Run all three, refreshing DBs/rules first.
- Implement the normalizer and dedup logic from §5.
- **DoD:** one scan returns a single deduplicated list spanning all three scanners with
  correct categories.

### Phase 4 — LLM triage layer
- For each finding (batched), send the LLM: the finding metadata + surrounding code context.
- Ask it to: re-rank severity, flag likely false positives, write a plain-English explanation
  grounded in the actual code. Store results back on the Finding.
- Keep prompts in `/backend/prompts/` as versioned files, not inline strings.
- **DoD:** findings come back with `triaged_severity`, `likely_false_positive`, and
  `explanation` populated; obvious false positives in the test repo get flagged.

### Phase 5 — LLM patch generation
- For each non-false-positive finding, send the LLM the vulnerable code + fix guidance and
  ask for a **unified diff** plus rationale. Validate the diff applies cleanly (`git apply --check`).
- **DoD:** at least one suggested patch for the test repo applies cleanly and visibly fixes the issue.

### Phase 6 — Frontend
- Submit-scan screen → job progress → results dashboard.
- Results grouped by category, sorted by triaged severity, false positives collapsed by default.
- Each finding expands to show explanation + the suggested diff with syntax highlighting.
- **DoD:** full flow works in the browser against the test repo.

### Phase 7 — Hardening
- Tighten the sandbox (read-only FS, dropped capabilities, seccomp, hard timeouts).
- Rate-limit scan submissions. Cap repo size. Scheduled DB freshness job.
- Cache LLM triage by finding hash to control cost.
- **DoD:** documented threat model; submitting a malicious repo cannot escape the sandbox.

---

## 7. LLM prompt design notes

- **Triage and patch-gen are separate calls.** Don't ask one prompt to do both.
- Always give the model **real surrounding code**, not just the one flagged line — context
  is what separates a real finding from a false positive.
- For SCA/CVE findings, include the advisory text/references in context so the explanation
  reflects the actual exploit mechanism rather than the model's stale memory. Give the model
  web search for very recent CVEs.
- Ask for structured output (JSON for triage; a fenced unified diff for patches) and validate it.
- Never let a suggested patch be auto-applied — always human-in-the-loop. Present, don't commit.

---

## 8. Hard rules (security-critical)

1. **All scanning runs inside an ephemeral, sandboxed container.** Untrusted code never
   touches the host or a long-lived worker.
2. **Suggested patches are never auto-applied.** Display only.
3. **Secrets found during scans are redacted in logs and the DB**, never echoed in full.
4. **Refresh scanner databases before every scan**; a stale DB silently misses recent CVEs.

---

## 9. First message to give Claude Code

> "Read BUILD_PLAN.md. Implement Phase 0 only. Stop at its Definition of Done and show me how
> to verify it before continuing."
