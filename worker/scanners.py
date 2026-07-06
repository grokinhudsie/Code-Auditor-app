"""Run scanners inside the sandbox and return raw SARIF text.

Each scanner runs in its own ephemeral container against the read-only repo
mount. Network is granted only where the scanner must refresh rules/DBs
(BUILD_PLAN hard rule 4); reading results back is always networkless.
"""

import sandbox

SEMGREP_IMAGE = "semgrep/semgrep:latest"
TRIVY_IMAGE = "aquasec/trivy:latest"
GITLEAKS_IMAGE = "zricethezav/gitleaks:latest"


def _volumes(volume_name: str, repo_mode: str = "ro") -> dict:
    return {volume_name: {"bind": "/workspace", "mode": "rw"}}


def read_result_file(volume_name: str, path: str) -> str:
    """Cat a result file out of the workspace from a networkless container."""
    _, logs = sandbox.run_sandboxed(
        sandbox.CLONE_IMAGE,
        entrypoint=["sh"],
        command=["-c", f"cat /workspace/results/{path} 2>/dev/null"],
        volumes={volume_name: {"bind": "/workspace", "mode": "ro"}},
        timeout=120,
        stderr_in_logs=False,
    )
    return logs


def run_semgrep(volume_name: str) -> str:
    """SAST scan with the community ruleset; rules are fetched fresh per run."""
    sandbox.refresh_image(SEMGREP_IMAGE)
    sandbox.run_sandboxed(
        SEMGREP_IMAGE,
        command=[
            "semgrep", "scan",
            "--config", "p/default",
            "--sarif", "--output", "/workspace/results/semgrep.sarif",
            "--metrics", "off",
            "--quiet",
            ".",
        ],
        working_dir="/workspace/repo",
        volumes=_volumes(volume_name),
        network_mode="bridge",  # rule registry fetch
        mem_limit="2g",
        timeout=1800,
    )
    return read_result_file(volume_name, "semgrep.sarif")


def run_trivy(volume_name: str) -> str:
    """SCA + secrets + IaC. `trivy fs` refreshes its vuln DB by default; the
    scan needs egress for that pull."""
    sandbox.refresh_image(TRIVY_IMAGE)
    sandbox.run_sandboxed(
        TRIVY_IMAGE,
        command=[
            "fs",
            "--scanners", "vuln,secret,misconfig",
            "--format", "sarif",
            "--output", "/workspace/results/trivy.sarif",
            "--no-progress",
            # Default mirror.gcr.io mirror is flaky; use the canonical DB repos.
            "--db-repository", "ghcr.io/aquasecurity/trivy-db:2",
            "--java-db-repository", "ghcr.io/aquasecurity/trivy-java-db:1",
            "/workspace/repo",
        ],
        volumes=_volumes(volume_name),
        network_mode="bridge",  # vuln DB refresh
        mem_limit="2g",
        timeout=1800,
        # Cache on the workspace volume, not the small tmpfs /tmp — the
        # decompressed vuln DB is far larger than the tmpfs size cap.
        environment={"TRIVY_CACHE_DIR": "/workspace/.trivycache"},
    )
    return read_result_file(volume_name, "trivy.sarif")


def run_gitleaks(volume_name: str) -> str:
    """Dedicated secret scan. gitleaks exits 1 when leaks are found, which is
    not an error for us (check=False)."""
    sandbox.refresh_image(GITLEAKS_IMAGE)
    sandbox.run_sandboxed(
        GITLEAKS_IMAGE,
        command=[
            "detect",
            "--source", "/workspace/repo",
            "--report-format", "sarif",
            "--report-path", "/workspace/results/gitleaks.sarif",
            "--no-banner",
            "--exit-code", "0",
        ],
        volumes=_volumes(volume_name),
        network_mode="none",  # gitleaks ships its rules in the image
        mem_limit="1g",
        timeout=900,
        check=False,
    )
    return read_result_file(volume_name, "gitleaks.sarif")
