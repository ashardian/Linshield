"""Firewall status overview.

Windows Defender surfaces firewall state; LinShield does the same for the
common Linux firewall front-ends. Detection is read-only by default: we report
which backend is active and whether it appears to be filtering. Enabling a
firewall is left to an explicit, opt-in action because it can lock a user out
of a remote box.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

# Firewall front-ends usually live in sbin dirs that aren't on a normal user's
# PATH, so search these explicitly when locating the binaries.
_SBIN = "/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin"


def _which(name: str) -> str | None:
    path = os.environ.get("PATH", "")
    return shutil.which(name, path=path + os.pathsep + _SBIN)


@dataclass(slots=True)
class FirewallStatus:
    backend: str
    active: bool
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {"backend": self.backend, "active": self.active, "detail": self.detail}


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv
            cmd, capture_output=True, text=True, timeout=15, check=False
        )
        return proc.returncode, (proc.stdout + proc.stderr)
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def _needs_root(out: str) -> bool:
    low = out.lower()
    return "permission denied" in low or "must be root" in low or "need to be root" in low


def status() -> FirewallStatus:
    """Best-effort detection of the active firewall and its state.

    Querying firewall state generally requires root; when LinShield runs as a
    normal user we still report which backend is *present* rather than claiming
    none exists.
    """
    ufw = _which("ufw")
    if ufw:
        code, out = _run([ufw, "status"])
        if code == 0:
            active = "status: active" in out.lower()
            return FirewallStatus(
                backend="ufw",
                active=active,
                detail="ufw is active and enforcing rules."
                if active
                else "ufw is installed but inactive.",
            )
        return FirewallStatus(
            backend="ufw",
            active=False,
            detail="ufw is installed; run as root to read its state."
            if _needs_root(out)
            else "ufw is installed (state unknown).",
        )

    fwcmd = _which("firewall-cmd")
    if fwcmd:
        code, out = _run([fwcmd, "--state"])
        active = code == 0 and "running" in out
        return FirewallStatus(
            backend="firewalld",
            active=active,
            detail="firewalld is running." if active else "firewalld is installed (not running / needs root).",
        )

    nft = _which("nft")
    if nft:
        code, out = _run([nft, "list", "ruleset"])
        if code == 0:
            has_rules = bool(out.strip()) and ("chain" in out or "table" in out)
            return FirewallStatus(
                backend="nftables",
                active=has_rules,
                detail="nftables has an active ruleset."
                if has_rules
                else "nftables present but no ruleset loaded.",
            )
        return FirewallStatus(
            backend="nftables",
            active=False,
            detail="nftables is installed; run as root to read the ruleset."
            if _needs_root(out)
            else "nftables is installed (state unknown).",
        )

    ipt = _which("iptables")
    if ipt:
        code, out = _run([ipt, "-S"])
        if code == 0:
            rule_lines = [ln for ln in out.splitlines() if ln.startswith("-A")]
            active = bool(rule_lines)
            return FirewallStatus(
                backend="iptables",
                active=active,
                detail=f"iptables has {len(rule_lines)} rule(s)."
                if active
                else "iptables present with default (open) policy.",
            )
        return FirewallStatus(
            backend="iptables",
            active=False,
            detail="iptables is installed; run as root to read its rules."
            if _needs_root(out)
            else "iptables is installed (state unknown).",
        )

    return FirewallStatus(
        backend="none",
        active=False,
        detail="No supported firewall front-end detected (ufw/firewalld/nftables/iptables).",
    )
