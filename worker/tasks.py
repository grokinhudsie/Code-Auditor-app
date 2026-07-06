"""Scan job functions executed by the RQ worker.

Phase 1 will add the real scan task (clone repo into sandbox, run scanners).
"""


def ping() -> str:
    return "pong"
