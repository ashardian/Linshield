"""Rootkit and indicator-of-compromise (IOC) checks.

A lightweight, dependency-light pass over common Linux persistence and
rootkit tells: ``/etc/ld.so.preload`` injection, known rootkit file paths,
hidden processes (PIDs in ``/proc`` that ``psutil`` cannot enumerate),
promiscuous network interfaces and suspicious listening sockets. This is a
triage aid, not a replacement for chkrootkit/rkhunter — and it will say so.
"""

from __future__ import annotations

# LS-SELF-EXCLUDE-7f3a9c2e1b — LinShield-owned file; excluded from self-scanning.

import os
from pathlib import Path

from .models import Finding, Severity

try:
    import psutil  # type: ignore

    _PSUTIL = True
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore
    _PSUTIL = False

# Paths historically dropped by well-known Linux rootkits/backdoors. Drawn from
# chkrootkit/rkhunter reference signatures (Adore, Knark, t0rn, SuckIT, Tuxkit,
# Diamorphine, Reptile, Beurk, Jynx and friends).
_KNOWN_ROOTKIT_PATHS = (
    "/dev/.lib", "/dev/.hdlc", "/dev/.udev", "/dev/.initramfs/.x",
    "/dev/shm/.x", "/dev/shm/.ssh", "/dev/.kobjects",
    "/usr/share/.aPa", "/usr/lib/.fx", "/usr/lib/.libgh-gh",
    "/usr/lib/libgh.so", "/usr/lib/.kinteg", "/usr/lib/.wormie",
    "/lib/.so", "/lib/defs", "/lib/libgh.so", "/lib/ldd.so/tk",
    "/lib/modules/.reptile", "/lib/udev/.initramfs",
    "/etc/rc.d/init.d/rc.modules", "/etc/ld.so.hash", "/etc/.enyelkmHIDE",
    "/etc/rc.d/rc.local.bak", "/etc/.pwd.lock-",
    "/tmp/.ICE-unix/.X11", "/tmp/.font-unix/.cache", "/tmp/.dump",
    "/tmp/.../", "/tmp/.,!", "/tmp/.bugtraq", "/tmp/.cheese",
    "/usr/bin/.etc", "/usr/bin/ddc", "/usr/bin/sourcemask",
    "/usr/sbin/.../", "/var/spool/.../", "/usr/include/rpcsvc/du",
    "/usr/include/.../", "/usr/include/file.h", "/usr/include/hosts.h",
    "/proc/knark", "/proc/.reptile",
)

_SUSPICIOUS_PRELOAD_HINT = "/etc/ld.so.preload"


def _check_ld_preload() -> list[Finding]:
    findings: list[Finding] = []
    preload = Path(_SUSPICIOUS_PRELOAD_HINT)
    if preload.exists():
        try:
            content = preload.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            content = "<unreadable>"
        findings.append(
            Finding(
                category="rootkit",
                title="/etc/ld.so.preload is present",
                severity=Severity.HIGH,
                detail=(
                    "This file forces libraries into every dynamically-linked "
                    f"process and is a classic rootkit hook. Contents: {content!r}. "
                    "Confirm each library is legitimate."
                ),
            )
        )
    env_preload = os.environ.get("LD_PRELOAD")
    if env_preload:
        findings.append(
            Finding(
                category="rootkit",
                title="LD_PRELOAD set in the environment",
                severity=Severity.MEDIUM,
                detail=f"LD_PRELOAD={env_preload!r} — verify this is intentional.",
            )
        )
    return findings


def _check_known_paths() -> list[Finding]:
    findings: list[Finding] = []
    for raw in _KNOWN_ROOTKIT_PATHS:
        if Path(raw).exists():
            findings.append(
                Finding(
                    category="rootkit",
                    title=f"Known rootkit artefact present: {raw}",
                    severity=Severity.CRITICAL,
                    detail="Path matches a file dropped by documented Linux rootkits.",
                )
            )
    return findings


def _check_hidden_processes() -> list[Finding]:
    """Compare PIDs visible in /proc with what psutil can enumerate."""
    findings: list[Finding] = []
    proc = Path("/proc")
    if not proc.is_dir() or not _PSUTIL:
        return findings
    try:
        proc_pids = {int(p.name) for p in proc.iterdir() if p.name.isdigit()}
    except OSError:
        return findings
    visible = set(psutil.pids())  # type: ignore[union-attr]
    hidden = proc_pids - visible
    # A small race-window difference is normal; flag only a notable gap.
    if len(hidden) > 2:
        findings.append(
            Finding(
                category="rootkit",
                title=f"{len(hidden)} PID(s) in /proc not enumerable by the process API",
                severity=Severity.MEDIUM,
                detail=(
                    f"Possible hidden processes (PIDs: {sorted(hidden)[:10]}...). "
                    "Some difference is expected on busy systems; investigate if persistent."
                ),
            )
        )
    return findings


def _check_promiscuous_nics() -> list[Finding]:
    findings: list[Finding] = []
    net = Path("/sys/class/net")
    if not net.is_dir():
        return findings
    for iface in net.iterdir():
        flags_file = iface / "flags"
        try:
            flags = int(flags_file.read_text().strip(), 16)
        except (OSError, ValueError):
            continue
        # IFF_PROMISC == 0x100
        if flags & 0x100:
            findings.append(
                Finding(
                    category="rootkit",
                    title=f"Interface {iface.name} is in promiscuous mode",
                    severity=Severity.MEDIUM,
                    detail="Promiscuous mode can indicate a packet sniffer. Expected only for IDS/capture tools.",
                )
            )
    return findings


def _check_listening_sockets() -> list[Finding]:
    findings: list[Finding] = []
    if not _PSUTIL:
        return findings
    try:
        conns = psutil.net_connections(kind="inet")  # type: ignore[union-attr]
    except (psutil.AccessDenied, PermissionError):  # type: ignore[union-attr]
        return [
            Finding(
                category="network",
                title="Listening-socket inspection requires elevated privileges",
                severity=Severity.INFO,
                detail="Re-run as root for full socket attribution.",
            )
        ]
    except Exception:  # pragma: no cover - psutil platform quirks
        return findings
    # Listening sockets are summarised by the engine; rootkit module only
    # raises a finding when binding to all interfaces on a high/odd port.
    suspicious = [
        c
        for c in conns
        if c.status == "LISTEN"
        and c.laddr
        and c.laddr.ip in ("0.0.0.0", "::")
        and c.laddr.port not in (22, 53, 80, 443, 631, 8920)
        and c.laddr.port > 1024
    ]
    for c in suspicious[:10]:
        findings.append(
            Finding(
                category="network",
                title=f"Service listening on all interfaces at port {c.laddr.port}",
                severity=Severity.LOW,
                detail=f"PID {c.pid} bound 0.0.0.0:{c.laddr.port}. Confirm this exposure is intended.",
            )
        )
    return findings


def _check_deleted_exe_processes() -> list[Finding]:
    """Flag running processes whose executable has been deleted from disk.

    A process backed by a deleted inode (``/proc/<pid>/exe`` → ``... (deleted)``)
    is a classic fileless / memory-resident persistence tell — e.g. a miner that
    unlinked its own binary after launch. Some legitimate cases exist (a binary
    upgraded in place while still running), so this is reported, not auto-acted.
    """
    findings: list[Finding] = []
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return findings
    flagged = 0
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        exe = entry / "exe"
        try:
            target = os.readlink(exe)
        except (OSError, PermissionError):
            continue
        if target.endswith(" (deleted)"):
            # Ignore the common benign case of /memfd: and shared-memory maps that
            # are not really "deleted on disk" persistence.
            real = target[: -len(" (deleted)")]
            if real.startswith(("/memfd:", "/dev/zero", "/[aio]", "/SYSV")):
                continue
            flagged += 1
            if flagged > 25:
                continue
            try:
                comm = (entry / "comm").read_text(errors="replace").strip()
            except OSError:
                comm = "?"
            findings.append(
                Finding(
                    category="process",
                    title=f"Process running from a deleted executable (PID {entry.name})",
                    severity=Severity.HIGH,
                    detail=(
                        f"'{comm}' (PID {entry.name}) executes '{real}', which no "
                        f"longer exists on disk — a common fileless-malware tell. "
                        f"Verify it isn't a miner/backdoor before dismissing."
                    ),
                )
            )
    return findings


def _check_kernel_taint() -> list[Finding]:
    """Report a tainted kernel (out-of-tree or force-loaded modules)."""
    taint_file = Path("/proc/sys/kernel/tainted")
    try:
        value = int(taint_file.read_text().strip())
    except (OSError, ValueError):
        return []
    if value == 0:
        return []
    bits = []
    if value & (1 << 0):
        bits.append("proprietary module (G/P)")
    if value & (1 << 1):
        bits.append("force-loaded module")
    if value & (1 << 12):
        bits.append("out-of-tree module")
    if value & (1 << 13):
        bits.append("unsigned module")
    detail = (
        f"Kernel taint flags = {value}"
        + (f" ({', '.join(bits)})" if bits else "")
        + ". Often benign (GPU/VM drivers), but unsigned/out-of-tree modules "
        "warrant a glance at `lsmod` for anything unexpected."
    )
    sev = Severity.MEDIUM if (value & ((1 << 12) | (1 << 13) | (1 << 1))) else Severity.INFO
    return [Finding(category="kernel", title="Kernel is tainted", severity=sev, detail=detail)]


def run_checks() -> list[Finding]:
    """Run every IOC check and return the combined findings."""
    findings: list[Finding] = []
    findings.extend(_check_ld_preload())
    findings.extend(_check_known_paths())
    findings.extend(_check_hidden_processes())
    findings.extend(_check_promiscuous_nics())
    findings.extend(_check_listening_sockets())
    findings.extend(_check_deleted_exe_processes())
    findings.extend(_check_kernel_taint())
    # "All clear" only when nothing above INFO was raised.
    if not any(f.severity is not Severity.INFO for f in findings):
        findings.append(
            Finding(
                category="rootkit",
                title="No rootkit indicators found",
                severity=Severity.INFO,
                detail="Built-in IOC checks passed. For deeper assurance also run rkhunter/chkrootkit.",
            )
        )
    return findings
