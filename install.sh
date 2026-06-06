#!/usr/bin/env bash
# LinShield installer.
# Installs the Python package and optionally sets up systemd units.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
say()  { echo -e "${GREEN}[linshield]${NC} $*"; }
warn() { echo -e "${YELLOW}[linshield]${NC} $*"; }

# --- python check ---------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required but not found." >&2; exit 1
fi
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info[:2] >= (3,10) else 0)')
if [ "$PY_OK" != "1" ]; then
  echo "Python 3.10+ is required." >&2; exit 1
fi

# --- pip install ----------------------------------------------------------
PIP_ARGS=""
if python3 -c 'import sys; sys.exit(0)' && pip3 install --help 2>/dev/null | grep -q 'break-system-packages'; then
  PIP_ARGS="--break-system-packages"
fi

# Remove stale build artifacts so an in-place reinstall never fails on a
# locked/old egg-info directory.
rm -rf build dist ./*.egg-info linshield.egg-info 2>/dev/null || true

# Force a reinstall of LinShield itself ONLY (--force-reinstall --no-deps), so
# the package always updates in place — without trying to uninstall/replace
# dependencies that the OS installed via apt (those have no pip RECORD file and
# can't be removed by pip). Dependencies are then resolved normally, leaving
# already-satisfied (e.g. apt-provided) packages untouched.
EXTRA="full"
say "Installing LinShield (with [$EXTRA] extras: YARA + rich)…"
pip3 install $PIP_ARGS --force-reinstall --no-deps . >/dev/null 2>&1 || true
if ! pip3 install $PIP_ARGS ".[$EXTRA]" 2>/dev/null; then
  warn "Full extras unavailable (YARA build deps may be missing); installing core only."
  pip3 install $PIP_ARGS . || {
    echo "Install failed. Try a virtualenv: python3 -m venv .venv && . .venv/bin/activate && pip install '.[full]'" >&2
    exit 1
  }
fi

say "Installed. Try: linshield status"

# --- optional systemd setup ----------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  warn "Run as root to install systemd units (scheduled scan + real-time monitor)."
  exit 0
fi

if ! command -v systemctl >/dev/null 2>&1; then
  warn "systemd not detected; skipping service setup."
  exit 0
fi

read -r -p "Install systemd units for scheduled scans and real-time monitoring? [y/N] " ans
if [[ "${ans:-}" =~ ^[Yy]$ ]]; then
  BIN="$(command -v linshield || echo /usr/local/bin/linshield)"
  for unit in linshield-monitor.service linshield-scan.service linshield-scan.timer linshield-update.service linshield-update.timer; do
    sed "s#/usr/local/bin/linshield#${BIN}#g" "packaging/$unit" > "/etc/systemd/system/$unit"
  done
  systemctl daemon-reload
  systemctl enable --now linshield-monitor.service || warn "monitor service not started"
  systemctl enable --now linshield-scan.timer || warn "scan timer not started"
  systemctl enable --now linshield-update.timer || warn "update timer not started"
  say "systemd units installed. Status: systemctl status linshield-monitor"
fi
