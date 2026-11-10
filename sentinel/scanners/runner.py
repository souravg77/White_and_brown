"""Bounded, no-shell execution of a Kali tool.

Tools are run by absolute path with a fixed argument array, a wall-clock
timeout, and a cap on captured output. Target data is passed as arguments, never
interpolated into a shell string. This is the only place in the scanner layer
that launches a process.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolRun:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool


def run_tool(
    argv: list[str],
    *,
    timeout: int,
    max_output_bytes: int = 10 * 1024 * 1024,
) -> ToolRun:
    """Run ``argv`` (absolute path + fixed args). No shell, ever.

    Returns a :class:`ToolRun`; a timeout or a failure to launch is reported in
    the result rather than raised, so the adapter can record it as a scan
    failure instead of crashing the worker.
    """
    if not argv or "/" not in argv[0]:
        # Guard against a relative/ambiguous executable: adapters pass absolute
        # paths resolved by the tool registry.
        raise ValueError("run_tool requires an absolute executable path")
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or b""
        return ToolRun(
            exit_code=None,
            stdout=_decode(out, max_output_bytes)[0],
            stderr="timed out",
            timed_out=True,
            truncated=len(out) > max_output_bytes,
        )
    except OSError as exc:
        return ToolRun(None, "", str(exc), timed_out=False, truncated=False)

    stdout, t1 = _decode(proc.stdout, max_output_bytes)
    stderr, t2 = _decode(proc.stderr, max_output_bytes)
    return ToolRun(
        exit_code=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=False,
        truncated=t1 or t2,
    )


def _decode(data: bytes, cap: int) -> tuple[str, bool]:
    truncated = len(data) > cap
    return data[:cap].decode("utf-8", errors="replace"), truncated
