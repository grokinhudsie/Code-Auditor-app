"""Ephemeral sandbox containers for handling untrusted repos.

Every operation on untrusted code runs in a fresh container spawned via the
docker socket, never in the worker process itself. Containers are non-root,
CPU/memory/pid limited, hard-timed-out, and networkless unless the step
inherently needs egress (git clone, scanner DB refresh).
"""

import docker
import requests

CLONE_IMAGE = "alpine/git:2.47.2"

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
    check: bool = True,
) -> tuple[int, str]:
    """Run one command in a fresh container; return (exit_code, combined logs)."""
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
    )
    try:
        container.start()
        try:
            result = container.wait(timeout=timeout)
            exit_code = result.get("StatusCode", -1)
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            container.kill()
            raise SandboxError(f"sandbox step timed out after {timeout}s ({image})")
        logs = container.logs(stdout=True, stderr=True).decode(errors="replace")
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
        entrypoint=["chown"],
        command=["-R", SANDBOX_USER, "/workspace"],
        user="root",
        volumes={name: {"bind": "/workspace", "mode": "rw"}},
        timeout=60,
    )
    return name


def remove_workspace(volume_name: str) -> None:
    try:
        client().volumes.get(volume_name).remove(force=True)
    except docker.errors.NotFound:
        pass


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
