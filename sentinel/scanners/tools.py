"""Discovery of the security tools that ship with Kali Linux.

SENTINEL runs on Kali and uses the tooling already in the install rather than
bundling or reinstalling its own. This registry locates each tool by absolute
path, records its version from a startup health check, and reports a clear
availability status. A tool that is not present is reported ``missing`` so the
scan records it as ``skipped`` — results are never simulated.

Tools are always invoked by absolute path with fixed argument arrays. Target
data is passed as arguments, never interpolated into a shell string.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

# Candidate absolute paths per tool, in preference order. These are the standard
# locations in a Kali install; shutil.which is used as a fallback on PATH.
_KALI_TOOLS: dict[str, dict[str, object]] = {
    "nmap": {"paths": ["/usr/bin/nmap"], "version_args": ["--version"]},
    "httpx": {"paths": ["/usr/bin/httpx"], "version_args": ["-version"]},
    "testssl": {
        "paths": ["/usr/bin/testssl", "/usr/bin/testssl.sh"],
        "version_args": ["--version"],
    },
    "ssh-audit": {"paths": ["/usr/bin/ssh-audit"], "version_args": ["--help"]},
    "zap": {
        "paths": ["/usr/bin/zaproxy", "/usr/share/zaproxy/zap.sh"],
        "version_args": ["-version"],
    },
    "gitleaks": {"paths": ["/usr/bin/gitleaks"], "version_args": ["version"]},
    "trivy": {"paths": ["/usr/bin/trivy"], "version_args": ["--version"]},
    "semgrep": {"paths": ["/usr/bin/semgrep"], "version_args": ["--version"]},
    "subfinder": {"paths": ["/usr/bin/subfinder"], "version_args": ["-version"]},
    "dnsx": {"paths": ["/usr/bin/dnsx"], "version_args": ["-version"]},
}


@dataclass(frozen=True)
class ToolInfo:
    name: str
    path: str | None
    version: str
    available: bool

    @property
    def status(self) -> str:
        return "available" if self.available else "missing"


def _resolve_path(name: str, candidates: list[str]) -> str | None:
    for candidate in candidates:
        if shutil.which(candidate) or _is_executable(candidate):
            return candidate
    return shutil.which(name)


def _is_executable(path: str) -> bool:
    import os

    return os.path.isfile(path) and os.access(path, os.X_OK)


def _probe_version(path: str, version_args: list[str]) -> str:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed path, fixed args, no shell
            [path, *version_args],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    out = (proc.stdout or proc.stderr or "").strip().splitlines()
    return out[0].strip() if out else ""


def detect_tool(name: str) -> ToolInfo:
    spec = _KALI_TOOLS.get(name)
    if spec is None:
        return ToolInfo(name=name, path=None, version="", available=False)
    path = _resolve_path(name, list(spec["paths"]))  # type: ignore[arg-type]
    if path is None:
        return ToolInfo(name=name, path=None, version="", available=False)
    version = _probe_version(path, list(spec["version_args"]))  # type: ignore[arg-type]
    return ToolInfo(name=name, path=path, version=version, available=True)


def detect_all() -> dict[str, ToolInfo]:
    """Run a health check for every known tool. Call at startup and log results."""
    return {name: detect_tool(name) for name in _KALI_TOOLS}


def known_tools() -> list[str]:
    return list(_KALI_TOOLS)
