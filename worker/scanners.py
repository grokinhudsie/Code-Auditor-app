"""Run scanners inside the sandbox and return raw SARIF text.

Each scanner runs in its own ephemeral container against the read-only repo
mount. Network is granted only where the scanner must refresh rules/DBs
(BUILD_PLAN hard rule 4); reading results back is always networkless.
"""

import sandbox

SEMGREP_IMAGE = "semgrep/semgrep:latest"


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
