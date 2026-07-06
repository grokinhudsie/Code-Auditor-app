# Deploying VulnScanner

**Architecture:** frontend on Vercel, backend (API + worker + Redis + Postgres)
on a single DigitalOcean droplet running Docker Compose. The worker sandboxes
each scan by spawning Docker containers, so the backend needs a real Docker
host — this is why it runs on a VM and not on Vercel/Railway.

---

## 1. Create the droplet

- **Plan:** Basic, **4 GB RAM / 2 vCPU / 80 GB** ($24/mo). Don't go below 4 GB —
  Semgrep will OOM.
- **Image:** the **Docker** Marketplace image (Docker pre-installed) on
  Ubuntu 24.04.
- **Auth:** add your SSH key.
- Note the droplet's public IP.

## 2. Set up the app

SSH in (`ssh root@<DROPLET_IP>`) and run:

```bash
git clone https://github.com/grokinhudsie/Code-Auditor-app.git
cd Code-Auditor-app

# Create the environment file (see §3 for what to put in it)
cp .env.example .env
nano .env        # paste your real values

docker compose up -d --build
```

First build takes a few minutes (it also pulls the scanner images). Check it's
up:

```bash
docker compose ps
curl -s http://localhost:8000/health   # {"status":"ok"}
```

## 3. Environment (`.env`)

```
ANTHROPIC_API_KEY=sk-ant-...            # required for LLM triage/patches
ANTHROPIC_MODEL=claude-mythos-5         # or claude-fable-5 if no Glasswing access
FRONTEND_ORIGIN=https://your-app.vercel.app   # your Vercel URL (for CORS)
```

`FRONTEND_ORIGIN` must match your Vercel domain exactly, or the browser will
block API calls. Multiple origins can be comma-separated.

## 4. Expose the API

The API listens on port 8000. For a quick start, open the firewall to 8000; for
anything real, put it behind a reverse proxy with TLS (Caddy makes this a
two-line config) so the browser can call it over `https`.

Minimal (HTTP, testing only):

```bash
ufw allow 8000/tcp
```

Recommended (HTTPS via Caddy, needs a domain pointed at the droplet):

```bash
# Caddyfile
api.yourdomain.com {
    reverse_proxy localhost:8000
}
```

Then `FRONTEND_ORIGIN` stays your Vercel URL and the frontend calls
`https://api.yourdomain.com`.

## 5. Frontend on Vercel

- Import the repo in Vercel; set **Root Directory = `frontend`**.
- Add an environment variable:
  `NEXT_PUBLIC_API_BASE = https://api.yourdomain.com` (or `http://<DROPLET_IP>:8000`
  for HTTP testing).
- Deploy. Vercel gives you the URL you visit.

The frontend already reads `NEXT_PUBLIC_API_BASE` (falls back to
`http://localhost:8000` for local dev), so no code change is needed.

## 6. Lock it down (do this before sharing the URL)

The API has **no authentication** — anyone who can reach it can submit scans and
burn your Anthropic credits, and the worker runs untrusted code in sandboxes.
Before exposing publicly, at minimum:

- Restrict who can reach it (Cloudflare Access, a VPN, an IP allowlist, or a
  shared-secret header check), **or** keep the droplet's firewall closed to the
  public and only allow your Vercel deployment's egress.
- Treat the droplet as disposable and isolated — don't run anything else
  sensitive on it. See `THREAT_MODEL.md`.

## 7. Operations

```bash
docker compose logs -f worker    # watch scans run
docker compose pull && docker compose up -d --build   # update after a git pull
docker compose down              # stop (add -v to wipe the database)
```

Docker starts on boot, so the app comes back up automatically after a reboot.
