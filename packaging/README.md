# Packaging — Kali Linux / Debian desktop

SENTINEL targets Kali Linux and uses the security tools already in the Kali
install, so the package depends on those tools at runtime rather than bundling
them.

## Run from source (development)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[desktop,db]'
sentinel tools                 # Kali tool health check
sentinel-desktop               # launch the desktop UI
```

## .deb (planned)

A Debian package is the primary distribution format for Kali. The control file
will:

- depend on `python3 (>= 3.12)` and the PySide6 runtime;
- **recommend** the Kali scanner packages (`nmap`, `testssl.sh`, `ssh-audit`,
  `gitleaks`, `trivy`, …) rather than depend on them, so SENTINEL installs even
  if a tool is absent and reports it as `skipped`;
- install the `.desktop` entry and icon.

## AppImage (alternative)

A single-file AppImage is also planned for portability across Debian/Ubuntu
derivatives. It bundles the Python runtime and PySide6 but still uses the host's
installed security tools.

Both are built in a later phase; this directory holds the desktop entry and the
packaging plan.
