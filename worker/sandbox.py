"""Ephemeral sandbox containers for handling untrusted repos.

Every operation on untrusted code runs in a fresh container spawned via the
docker socket, never in the worker process itself. Containers are non-root,
CPU/memory/pid limited, hard-timed-out, and networkless unless the step
inherently needs egress (git clone, scanner DB refresh).
"""

import os
import re

import docker
import requests

CLONE_IMAGE = "alpine/git:2.47.2"
# Unpacking uses python rather than busybox unzip: busybox recreates symlink
# entries, which reopens zip-slip via a "link -> /workspace" entry followed by
# writes through it. The script below refuses symlinks outright.
UNPACK_IMAGE = "python:3.12-alpine"
UPLOADS_VOLUME = os.environ.get("UPLOADS_VOLUME", "vulnscan-uploads")
MAX_ZIP_ENTRIES = int(os.environ.get("MAX_ZIP_ENTRIES", "20000"))

_SCAN_ID_RE = re.compile(r"^[0-9a-f]{32}$")

SANDBOX_USER = "1000:1000"
DEFAULT_MEM = "1g"
DEFAULT_NANO_CPUS = 1_000_000_000  # 1 CPU

_client: docker.DockerClient | None = None


class SandboxError(Exception):
    pass


def client() -> docker.DockerClient:
    global _client
    if _client is None:
        _client = docker.from_env()
    return _client


def ensure_image(image: str) -> None:
    try:
        client().images.get(image)
    except docker.errors.ImageNotFound:
        client().images.pull(image)


def refresh_image(image: str) -> None:
    """Pull the latest tag; fall back to the cached image when offline."""
    try:
        client().images.pull(image)
    except docker.errors.APIError:
        client().images.get(image)  # raises if we have no copy at all


def run_sandboxed(
    image: str,
    command: list[str],
    *,
    volumes: dict | None = None,
    network_mode: str = "none",
    timeout: int = 300,
    user: str = SANDBOX_USER,
    entrypoint: list[str] | None = None,
    environment: dict | None = None,
    mem_limit: str = DEFAULT_MEM,
    working_dir: str | None = None,
    stderr_in_logs: bool = True,
    cap_add: list | None = None,
    check: bool = True,
) -> tuple[int, str]:
    """Run one command in a fresh container; return (exit_code, logs)."""
    ensure_image(image)
    container = client().containers.create(
        image,
        command=command,
        entrypoint=entrypoint,
        user=user,
        volumes=volumes or {},
        network_mode=network_mode,
        environment={"HOME": "/tmp", **(environment or {})},
        mem_limit=mem_limit,
        nano_cpus=DEFAULT_NANO_CPUS,
        pids_limit=256,
        tmpfs={"/tmp": "size=256m"},
        security_opt=["no-new-privileges"],
        cap_drop=["ALL"],  # scanners need no Linux capabilities
        cap_add=cap_add or [],  # trusted setup steps may re-add specific caps
        working_dir=working_dir,
    )
    try:
        container.start()
        try:
            result = container.wait(timeout=timeout)
            exit_code = result.get("StatusCode", -1)
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            container.kill()
            raise SandboxError(f"sandbox step timed out after {timeout}s ({image})")
        logs = container.logs(stdout=True, stderr=stderr_in_logs).decode(errors="replace")
    finally:
        container.remove(force=True)

    if check and exit_code != 0:
        raise SandboxError(
            f"sandbox step failed (exit {exit_code}, {image}): {logs[-2000:]}"
        )
    return exit_code, logs


def create_workspace(scan_id: str) -> str:
    """Create a per-scan named volume, owned by the sandbox user."""
    name = f"scan-{scan_id}"
    client().volumes.create(name)
    run_sandboxed(
        CLONE_IMAGE,
        entrypoint=["sh"],
        command=["-c", f"mkdir -p /workspace/results && chown -R {SANDBOX_USER} /workspace"],
        user="root",
        volumes={name: {"bind": "/workspace", "mode": "rw"}},
        timeout=60,
        cap_add=["CHOWN"],  # trusted step: chown the fresh volume to the sandbox user
    )
    return name


def remove_workspace(volume_name: str) -> None:
    try:
        client().volumes.get(volume_name).remove(force=True)
    except docker.errors.NotFound:
        pass


def read_source(volume_name: str, rel_path: str, start: int, end: int,
                pad: int = 8) -> str | None:
    """Return numbered source lines around [start, end] for LLM context.
    Runs networkless and read-only; rel_path is validated to stay in the repo."""
    if not rel_path or start is None:
        return None
    # Reject traversal / absolute paths before handing to the container.
    if rel_path.startswith("/") or ".." in rel_path.split("/"):
        return None
    lo = max(1, start - pad)
    hi = (end or start) + pad
    script = (
        f'cd /workspace/repo && f="./{rel_path}"; [ -f "$f" ] && '
        f'awk "NR>={lo} && NR<={hi} {{printf \\"%d: %s\\n\\", NR, \\$0}}" "$f" || true'
    )
    _, logs = run_sandboxed(
        CLONE_IMAGE,
        entrypoint=["sh"],
        command=["-c", script],
        volumes={volume_name: {"bind": "/workspace", "mode": "ro"}},
        timeout=60,
        stderr_in_logs=False,
        check=False,
    )
    return logs.strip() or None


def check_patch_applies(volume_name: str, diff: str) -> bool:
    """Validate a unified diff with `git apply --check` (BUILD_PLAN §5). The
    patch is never applied — only checked — and this runs networkless."""
    import base64

    # Pass the diff via base64 to avoid any shell-quoting issues with its content.
    b64 = base64.b64encode(diff.encode()).decode()
    script = (
        f'cd /workspace/repo && echo {b64} | base64 -d > /tmp/fix.patch && '
        f'git apply --check /tmp/fix.patch'
    )
    code, _ = run_sandboxed(
        CLONE_IMAGE,
        entrypoint=["sh"],
        command=["-c", script],
        volumes={volume_name: {"bind": "/workspace", "mode": "ro"}},
        timeout=60,
        check=False,
    )
    return code == 0


MAX_REPO_MB = int(os.environ.get("MAX_REPO_MB", "500"))


def clone_repo(volume_name: str, git_url: str) -> None:
    """Shallow-clone into /workspace/repo. Only sandbox step with egress."""
    run_sandboxed(
        CLONE_IMAGE,
        command=["clone", "--depth", "1", "--single-branch", git_url, "/workspace/repo"],
        volumes={volume_name: {"bind": "/workspace", "mode": "rw"}},
        network_mode="bridge",
        mem_limit="512m",
        timeout=300,
    )
    _enforce_repo_size(volume_name)


def copy_local_dir(volume_name: str, host_path: str) -> None:
    """Copy a directory from the docker HOST into /workspace/repo.

    The path was validated by shared.localpath in both the API and the worker.
    Runs as root with read caps because host files may not be readable by the
    sandbox uid; the source mount is read-only, so the host stays untouched.
    Note: if the path doesn't exist, the daemon auto-creates an empty dir at
    the bind source — the emptiness check below turns that into a clean error.
    """
    max_mb = MAX_REPO_MB
    script = (
        'if [ ! -d /src ] || [ -z "$(ls -A /src)" ]; then '
        'echo "local path not found or empty on host"; exit 1; fi; '
        f'size=$(du -sm /src | cut -f1); if [ "$size" -gt {max_mb} ]; then '
        f'echo "directory too large: ${{size}}MB > {max_mb}MB cap"; exit 1; fi; '
        f'mkdir -p /workspace/repo && cp -a /src/. /workspace/repo/ && '
        f'chown -R {SANDBOX_USER} /workspace/repo'
    )
    run_sandboxed(
        CLONE_IMAGE,
        entrypoint=["sh"],
        command=["-c", script],
        user="root",
        volumes={
            host_path: {"bind": "/src", "mode": "ro"},
            volume_name: {"bind": "/workspace", "mode": "rw"},
        },
        mem_limit="512m",
        timeout=600,
        cap_add=["CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER"],
    )
    _enforce_repo_size(volume_name)


_UNPACK_SCRIPT = r"""
import os, stat, sys, zipfile, zlib

src, dest = sys.argv[1], sys.argv[2]
max_mb, max_entries = int(sys.argv[3]), int(sys.argv[4])
budget = max_mb * 1024 * 1024

try:
    zf = zipfile.ZipFile(src)
except (zipfile.BadZipFile, OSError):
    sys.exit("not a valid zip archive")

infos = [
    i for i in zf.infolist()
    if not i.filename.startswith("__MACOSX/")
    and os.path.basename(i.filename) != ".DS_Store"
]
if not infos:
    sys.exit("archive is empty")
if len(infos) > max_entries:
    sys.exit("archive has too many entries: %d > %d" % (len(infos), max_entries))

# Cheap precheck on declared sizes. Headers can lie, so the real defense is the
# shrinking budget in the copy loop below.
declared = sum(i.file_size for i in infos)
if declared > budget:
    sys.exit("archive expands to %dMB, over the %dMB cap" % (declared // 1048576, max_mb))

# GitHub's "Download ZIP" wraps everything in <repo>-<branch>/. Strip a single
# shared top-level directory so finding paths match the user's own tree.
tops = {i.filename.split("/", 1)[0] for i in infos}
strip = len(tops) == 1 and any("/" in i.filename for i in infos)

dest_real = os.path.realpath(dest)
os.makedirs(dest_real, exist_ok=True)

for info in infos:
    original = info.filename
    mode = info.external_attr >> 16
    unix = info.create_system == 3
    if unix and stat.S_ISLNK(mode):
        sys.exit("archive contains a symlink: %s" % original)
    if "\\" in original or original.startswith("/") or ".." in original.split("/"):
        sys.exit("unsafe path in archive: %s" % original)

    name = original.split("/", 1)[1] if strip and "/" in original else original
    if not name or name == original and strip:
        continue

    target = os.path.realpath(os.path.join(dest_real, name))
    if target != dest_real and not target.startswith(dest_real + os.sep):
        sys.exit("unsafe path in archive: %s" % original)

    if info.is_dir():
        os.makedirs(target, exist_ok=True)
        continue
    # Many writers store permission bits with no file-type bits at all, so only
    # judge the type when S_IFMT actually says something.
    ftype = stat.S_IFMT(mode)
    if unix and ftype and ftype != stat.S_IFREG:
        sys.exit("archive contains a special file: %s" % original)

    os.makedirs(os.path.dirname(target), exist_ok=True)
    try:
        entry = zf.open(info)
    except RuntimeError:
        sys.exit("password-protected archives are not supported")
    except (zipfile.BadZipFile, EOFError, OSError, zlib.error) as exc:
        sys.exit("unreadable entry %s: %s" % (original, exc))
    try:
        out = open(target, "wb")
    except OSError as exc:
        sys.exit("could not write %s: %s" % (name, exc))
    # Read and write failures are reported separately: they mean completely
    # different things (a bad archive vs. a bad destination) and lumping them
    # together makes the error useless. SystemExit is a BaseException, so the
    # budget check still propagates through these handlers.
    with entry, out:
        while True:
            try:
                chunk = entry.read(65536)
            except (zipfile.BadZipFile, EOFError, zlib.error) as exc:
                sys.exit("corrupt entry %s: %s" % (original, exc))
            if not chunk:
                break
            budget -= len(chunk)
            if budget < 0:
                sys.exit("archive expands beyond the %dMB cap" % max_mb)
            try:
                out.write(chunk)
            except OSError as exc:
                sys.exit("could not write %s: %s" % (name, exc))
"""


def unpack_zip(volume_name: str, scan_id: str) -> None:
    """Extract an uploaded archive into /workspace/repo.

    The archive is untrusted and nothing outside a sandbox ever opens it: the
    API only counts bytes on the way in, and the worker only unlinks the file
    afterwards. The extractor refuses symlinks, traversal paths and special
    files, and copies with a shrinking byte budget so a bomb dies mid-stream
    instead of after filling the volume. Runs non-root with no added caps --
    create_workspace already chowned /workspace to the sandbox uid.
    """
    if not _SCAN_ID_RE.match(scan_id):
        raise SandboxError(f"invalid scan id: {scan_id}")
    run_sandboxed(
        UNPACK_IMAGE,
        entrypoint=["python3"],
        command=[
            "-c",
            _UNPACK_SCRIPT,
            f"/upload/{scan_id}.zip",
            "/workspace/repo",
            str(MAX_REPO_MB),
            str(MAX_ZIP_ENTRIES),
        ],
        volumes={
            UPLOADS_VOLUME: {"bind": "/upload", "mode": "ro"},
            volume_name: {"bind": "/workspace", "mode": "rw"},
        },
        network_mode="none",
        mem_limit="512m",
        timeout=600,
    )
    _enforce_repo_size(volume_name)


def has_git_dir(volume_name: str) -> bool:
    """True when /workspace/repo is a git repo (drives gitleaks mode)."""
    code, _ = run_sandboxed(
        CLONE_IMAGE,
        entrypoint=["sh"],
        command=["-c", "test -d /workspace/repo/.git"],
        volumes={volume_name: {"bind": "/workspace", "mode": "ro"}},
        timeout=60,
        check=False,
    )
    return code == 0


def _enforce_repo_size(volume_name: str) -> None:
    """Reject oversized repos (zip-bomb / disk-exhaustion guard, BUILD_PLAN §7)."""
    _, logs = run_sandboxed(
        CLONE_IMAGE,
        entrypoint=["sh"],
        command=["-c", "du -sm /workspace/repo | cut -f1"],
        volumes={volume_name: {"bind": "/workspace", "mode": "ro"}},
        timeout=120,
        stderr_in_logs=False,
    )
    try:
        size_mb = int(logs.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return  # couldn't measure; don't block the scan
    if size_mb > MAX_REPO_MB:
        raise SandboxError(f"repo too large: {size_mb}MB > {MAX_REPO_MB}MB cap")


def list_file_tree(volume_name: str, limit: int = 2000) -> list[str]:
    """List repo files from a networkless container."""
    _, logs = run_sandboxed(
        CLONE_IMAGE,
        entrypoint=["sh"],
        command=[
            "-c",
            "cd /workspace/repo && find . -type f -not -path './.git/*' | sed 's|^\\./||' | sort",
        ],
        volumes={volume_name: {"bind": "/workspace", "mode": "ro"}},
        timeout=60,
    )
    files = [line for line in logs.splitlines() if line.strip()]
    return files[:limit]
