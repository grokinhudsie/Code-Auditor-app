# VulnScan Code Auditor — Threat Model

The core risk: **we execute security scanners over untrusted, attacker-supplied
code.** A submitted repository is hostile input. This document states what we
defend against, how, and what remains out of scope.

## Assets

- The host running the worker and the Docker daemon.
- The Postgres database (scan history, findings — including redacted secrets).
- **User account data**: emails, GitHub ids, WebAuthn public keys, session
  hashes. No passwords are stored (passkeys + OAuth only), session cookies are
  stored only as SHA-256 hashes, and the GitHub OAuth access token is used
  once and discarded.
- The Anthropic API key used for triage/patch generation.
- Availability of the service for other users.

## Trust boundaries

```
untrusted repo ──► ephemeral sandbox container ──► normalized findings ──► DB ──► UI
                   (non-root, capped, networkless)
```

Everything to the left of the sandbox is untrusted. The sandbox is the boundary;
nothing from a scanned repo is ever executed on the host or in the long-lived
worker process.

## Threats and mitigations

| # | Threat | Mitigation |
|---|--------|------------|
| T1 | Malicious repo executes code to escape onto the host | All scanning runs in **ephemeral containers** spawned per step. Never run scanners in the worker or on the host. |
| T2 | Container breakout via privileges | Containers run **non-root** (`1000:1000`), **`cap_drop: ALL`**, `no-new-privileges`, and a fresh container per step (`--rm`). |
| T3 | Data exfiltration / SSRF / callbacks from scanned code | Scan steps run with **`network=none`**. Egress is granted **only** to the git clone and scanner DB/rule refresh steps, which run the tool — not repo code. |
| T4 | Resource exhaustion (fork bombs, huge repos, zip bombs) | Per-container `mem_limit`, `nano_cpus`, `pids_limit`, `tmpfs` size cap, and a hard wall-clock **timeout** on every step. Clones are shallow (`--depth 1`) and **repo size is capped** after clone. |
| T5 | Git URL abuse (`file://`, `ssh://`, option injection like `--upload-pack`) | API and worker both validate against a strict **https-only regex**; the URL is passed as a positional arg, never interpolated into a shell. |
| T6 | Denial of service by flooding scan submissions | **Per-IP rate limiting** on `POST /scans` (Redis sliding window). |
| T7 | Leaked secrets echoed into logs/DB/UI | Secret-category findings have their snippet **redacted** at normalization (`redact_secret`); the raw value is never stored or logged. |
| T8 | Malicious "fix" auto-applied to a repo | Suggested patches are **display-only**. They are validated with `git apply --check` but never applied. Human-in-the-loop by design. |
| T9 | Stale scanner databases silently miss recent CVEs | Scanner images and vuln DBs are **refreshed before every scan** (`refresh_image`, Trivy DB pull). |
| T10 | Docker socket access from the worker is itself powerful | The worker holds the docker socket to spawn sandboxes; it does not run untrusted code itself. Treat the worker as trusted and isolate it from the API's request path (separate container). |
| T11 | Prompt injection in repo content steering the LLM | The LLM only triages/explains and proposes diffs that are validated before display; it has no tools and cannot act. Worst case is a misleading explanation, not code execution. |
| T12 | Session/account attacks (CSRF, session theft, credential stuffing) | Sessions are httpOnly `SameSite=Lax` cookies with only their **SHA-256 hash** stored server-side; state-changing routes also check the `Origin` header. No passwords exist to stuff — auth is WebAuthn (phishing-resistant, challenges single-use with 5-min TTL) or GitHub OAuth (CSRF-protected by a `state` cookie; redirect target validated against open redirects). Auth endpoints are rate-limited per real client IP, and verification codes allow 5 attempts before invalidation. |
| T13 | Scan-result disclosure via leaked links | `GET /scans/{id}` is deliberately a **capability URL** (unguessable 32-hex id, readable by any link-holder) to keep results shareable and anonymous scans usable. Only the per-user history listing is authenticated. Treat a result link as containing the findings themselves. |

## Residual risk / out of scope

- **Kernel 0-day container escapes.** We rely on the container runtime's
  isolation; a kernel exploit could still break out. Run the worker host as a
  disposable VM in production and keep it patched.
- **The worker's docker-socket access.** Anyone who compromises the worker
  process controls the daemon. The worker must stay off the untrusted-input
  execution path (it already does — repo code only ever runs in child sandboxes).
- **Supply-chain trust in the scanner images themselves.** We pull official
  images; pin digests in a hardened deployment.
- **Cost abuse of the LLM layer.** Mitigated by triage caching (by finding hash)
  and rate limiting, but a determined attacker submitting many unique repos still
  incurs cost. Add auth/quotas before exposing publicly.

## Verification

The Phase 7 DoD check: submit a repo that attempts network egress and host
access from within a scan; confirm `network=none` blocks it and the sandbox
cannot reach the host or the internet. See `docs/verify-sandbox.md` for the
commands.
