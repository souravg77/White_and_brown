"""SENTINEL AI desktop shell (phase 1 scaffolding).

A minimal PySide6 window for the Kali desktop build. Phase 1 wires up only what
proves the shape: it loads the target allowlist, shows the active operating mode
(White Hat by default), and runs the Kali tool health check so the operator can
see which scanners are available. Scan controls, findings views and report
export are built in later phases.

PySide6 is an optional extra (``pip install .[desktop]``); importing this module
without it gives a clear message instead of a traceback.
"""

from __future__ import annotations

import sys
from pathlib import Path

from sentinel import __version__, load_config
from sentinel.modes import Mode
from sentinel.scanners.tools import detect_all

DEFAULT_CONFIG = Path("config/targets.yaml")
EXAMPLE_CONFIG = Path("config/targets.example.yaml")


def _load_targets():
    path = DEFAULT_CONFIG if DEFAULT_CONFIG.exists() else EXAMPLE_CONFIG
    try:
        return path, load_config(path)
    except Exception as exc:  # noqa: BLE001 - surfaced in the UI
        return path, exc


def build_window():
    try:
        from PySide6.QtWidgets import (
            QLabel,
            QMainWindow,
            QPlainTextEdit,
            QVBoxLayout,
            QWidget,
        )
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise SystemExit(
            "PySide6 is not installed. Install the desktop extra:\n"
            "    pip install '.[desktop]'"
        ) from exc

    window = QMainWindow()
    window.setWindowTitle(f"SENTINEL AI {__version__}")
    window.resize(720, 520)

    central = QWidget()
    layout = QVBoxLayout(central)

    layout.addWidget(QLabel(f"<h2>SENTINEL AI</h2>"))
    # The active mode is shown prominently and defaults to White Hat.
    layout.addWidget(QLabel(f"<b>Active mode:</b> {Mode.WHITE_HAT.value}"))

    path, cfg = _load_targets()
    report = QPlainTextEdit()
    report.setReadOnly(True)
    lines = [f"Config: {path}"]
    if isinstance(cfg, Exception):
        lines.append(f"  !! could not load targets: {cfg}")
    else:
        lines.append(f"Authorized targets ({len(cfg.targets)}):")
        for t in cfg.targets:
            lines.append(f"  - {t.domain}  checks={sorted(t.permitted_checks)}")
    lines.append("")
    lines.append("Kali tool health check:")
    for name, info in detect_all().items():
        detail = f"{info.path} ({info.version})" if info.available else "missing"
        lines.append(f"  [{info.status:>9}] {name}: {detail}")
    report.setPlainText("\n".join(lines))
    layout.addWidget(report)

    window.setCentralWidget(central)
    return window


def main() -> int:  # pragma: no cover - GUI entry point
    from PySide6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    window = build_window()
    window.show()
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
