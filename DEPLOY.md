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

## 3. Environment (`.env` on the droplet)

```
ANTHROPIC_API_KEY=sk-ant-...            # required for LLM triage/patches
ANTHROPIC_MODEL=claude-fable-5          # claude-mythos-5 only with Glasswing access
API_TOKEN=<paste output of: openssl rand -hex 32>   # protects the API
```

Generate the token once on the droplet:

```bash
openssl rand -hex 32
```

Put that value in `API_TOKEN` here **and** as `API_TOKEN` in Vercel (§5) — they
must match. Without a matching token, the frontend's requests get 401.

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
- Add **two** environment variables (both server-side — do NOT prefix with
  `NEXT_PUBLIC_`, so they never reach the browser):
  - `API_BASE = https://api.yourdomain.com` (or `http://<DROPLET_IP>:8000` for
    HTTP testing)
  - `API_TOKEN = <the same token you put in the droplet's .env>`
- Deploy. Vercel gives you the URL you visit.

The browser only ever talks to the Vercel app; Vercel's server proxies to your
droplet and adds the token. The token is never exposed to the browser, and
anyone hitting the droplet directly without it gets 401.

## 6. Lock it down (do this before sharing the URL)

The API requires the `API_TOKEN` bearer token (set it — see §3), so the droplet
won't accept scans from anyone who doesn't have it. Remaining hardening:

- **Anyone who can load your Vercel page can still submit scans** (the proxy
  submits on their behalf). If the app should be private to you, add a login/
  password gate on the frontend (e.g. Vercel's password protection, or a Basic-
  Auth middleware) so only you can reach it.
- Treat the droplet as disposable and isolated — don't run anything else
  sensitive on it. The worker runs untrusted code in sandboxes. See
  `THREAT_MODEL.md`.

## 7. Operations

```bash
docker compose logs -f worker    # watch scans run
docker compose pull && docker compose up -d --build   # update after a git pull
docker compose down              # stop (add -v to wipe the database)
```

Docker starts on boot, so the app comes back up automatically after a reboot.
