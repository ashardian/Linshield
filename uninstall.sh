#!/usr/bin/env bash
# LinShield uninstaller.
set -euo pipefail

YELLOW='\033[1;33m'; NC='\033[0m'
warn() { echo -e "${YELLOW}[linshield]${NC} $*"; }

# --- remove systemd units (root) ------------------------------------------
if [ "$(id -u)" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
  for unit in linshield-monitor.service linshield-scan.service linshield-scan.timer; do
    if [ -f "/etc/systemd/system/$unit" ]; then
      systemctl disable --now "$unit" 2>/dev/null || true
      rm -f "/etc/systemd/system/$unit"
      warn "removed $unit"
    fi
  done
  systemctl daemon-reload 2>/dev/null || true
fi

# --- pip uninstall --------------------------------------------------------
PIP_ARGS=""
if pip3 install --help 2>/dev/null | grep -q 'break-system-packages'; then
  PIP_ARGS="--break-system-packages"
fi
pip3 uninstall $PIP_ARGS -y linshield || warn "package not installed via pip"

# --- optional data removal ------------------------------------------------
read -r -p "Also remove LinShield data, config and quarantine? [y/N] " ans
if [[ "${ans:-}" =~ ^[Yy]$ ]]; then
  if [ "$(id -u)" -eq 0 ]; then
    rm -rf /etc/linshield /var/lib/linshield
  fi
  rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/linshield" \
         "${XDG_DATA_HOME:-$HOME/.local/share}/linshield"
  warn "data removed"
else
  warn "data left intact"
fi

warn "LinShield uninstalled."
