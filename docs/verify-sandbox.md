# Verifying sandbox isolation (Phase 7 DoD)

These checks confirm untrusted repo code cannot reach the host or the internet.

## 1. Network isolation (`network=none`)

Scanner steps run with `network=none`. Confirm a networkless container matching
our scan config cannot resolve DNS, reach the internet, or reach the host:

```bash
docker run --rm --network none --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges --entrypoint sh alpine/git:2.47.2 -c '
    wget -T 3 -q -O- https://example.com          && echo REACHED_INTERNET || echo NO_INTERNET
    wget -T 3 -q -O- http://host.docker.internal  && echo REACHED_HOST     || echo NO_HOST
  '
```

Expected: `NO_INTERNET` and `NO_HOST` (DNS resolution itself fails).

## 2. Non-root, no capabilities, no privilege escalation

```bash
docker run --rm --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  alpine:latest sh -c 'id; cat /proc/self/status | grep CapEff'
```

Expected: `uid=1000`, and `CapEff: 0000000000000000` (all capabilities dropped).

## 3. URL validation blocks non-https and option injection

```bash
for u in 'file:///etc/passwd' 'ssh://git@github.com/x/y' \
         '--upload-pack=touch /tmp/pwn' 'http://github.com/x/y'; do
  printf '%s -> %s\n' "$u" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:8000/scans \
       -H 'Content-Type: application/json' -d "{\"git_url\": \"$u\"}")"
done
```

Expected: every URL returns `422` (rejected before any container is spawned).

## 4. Rate limiting

Submit more than `SCAN_RATE_LIMIT` valid scans within the window; excess
requests return `429`.

## 5. Resource caps

Each sandbox container is created with `mem_limit`, `nano_cpus`, `pids_limit`,
a `tmpfs` size cap, and a hard wall-clock timeout. Repos larger than
`MAX_REPO_MB` (default 500) are rejected after clone. A fork bomb or infinite
loop in scanned code is bounded by `pids_limit` and the per-step timeout.
