"""Lightweight heuristic checks for individual files.

These complement signature matching by flagging *behaviourally* suspicious
files that may not match any known signature: executables hiding in temp
directories, unexpected SUID-root binaries, obfuscated scripts and so on.
Heuristics return SUSPICIOUS verdicts rather than INFECTED — they are hints,
not proof, and are surfaced separately in the UI.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from .models import Detection, Method, Severity, Verdict

# Directories where a freshly written native executable is unusual.
_SUSPECT_DIRS = ("/tmp", "/var/tmp", "/dev/shm")

# Standard, expected locations for SUID/SGID binaries on a Debian-like system.
_EXPECTED_SUID_PREFIXES = (
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
    "/opt/",
)

_SCRIPT_SHEBANGS = (b"#!/bin/sh", b"#!/bin/bash", b"#!/usr/bin/env", b"#!/usr/bin/python", b"#!/usr/bin/perl")

# Obfuscation / downloader patterns scanned in the first chunk of text files.
_TEXT_PATTERNS: tuple[tuple[re.Pattern[bytes], str, Severity], ...] = (
    (re.compile(rb"(curl|wget)[^\n]{0,80}\|\s*(sh|bash)"), "downloader-pipe-to-shell", Severity.HIGH),
    (re.compile(rb"base64\s+-d[^\n]{0,80}\|\s*(sh|bash)"), "base64-decode-to-shell", Severity.HIGH),
    (re.compile(rb"eval\s*\(\s*(base64|atob)"), "eval-of-decoded-data", Severity.HIGH),
    (re.compile(rb"/dev/tcp/\d"), "bash-reverse-shell", Severity.CRITICAL),
    (re.compile(rb"(nc|ncat)\s+-e\b"), "netcat-exec-shell", Severity.CRITICAL),
    (re.compile(rb"python[0-9.]*\s+-c\s+['\"][^\n]{0,300}socket[^\n]{0,200}(connect|dup2|/bin/(ba)?sh|subprocess\.|pty\.spawn)"), "python-reverse-shell-oneliner", Severity.HIGH),
    (re.compile(rb"chmod\s+\+s\b"), "setuid-bit-manipulation", Severity.MEDIUM),
    (re.compile(rb"history\s+-c|unset\s+HISTFILE"), "history-tampering", Severity.MEDIUM),
)

_HEAD_BYTES = 65536
_ELF_MAGIC = b"\x7fELF"

# Sentinel embedded in LinShield's own pattern-bearing files so the scanner
# never flags them as malicious. Real samples will not carry it.
_SELF_MARKER = b"LS-SELF-EXCLUDE-7f3a9c2e1b"

# Extensions that denote an actual runnable script. The content patterns below
# are only meaningful for code that can execute; applying them to documentation
# (.md/.rst/.txt) or markup (.html) produces noise — a README that documents a
# "curl ... | bash" install command is not malware.
_SCRIPT_EXTS = (
    ".sh", ".bash", ".zsh", ".ksh", ".dash",
    ".py", ".pyw", ".pl", ".rb", ".php", ".lua",
    ".js", ".mjs", ".cjs", ".ps1", ".psm1",
)


def _read_head(path: Path, n: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(n)
    except OSError:
        return b""


def inspect(path: Path, st: os.stat_result, head: bytes | None = None) -> list[Detection]:
    """Run all heuristics against a file already known to be a regular file.

    Args:
        path: File to inspect.
        st: Pre-fetched ``stat`` result (avoids a second syscall).
        head: Optional pre-read leading bytes; read here if not supplied.

    Returns:
        Zero or more SUSPICIOUS detections.
    """
    findings: list[Detection] = []
    mode = st.st_mode
    spath = str(path)

    if head is None:
        head = _read_head(path, _HEAD_BYTES)

    # Self-exclusion: never flag LinShield's own pattern-bearing files, which
    # carry this sentinel. (See _SELF_MARKER below — split so this very check
    # doesn't embed the literal twice.)
    if _SELF_MARKER in head:
        return findings

    is_elf = head[:4] == _ELF_MAGIC
    is_script = head.startswith(b"#!")

    # 1. Native executable living in a world-writable temp directory.
    if is_elf and spath.startswith(_SUSPECT_DIRS):
        findings.append(
            Detection(
                path=spath,
                verdict=Verdict.SUSPICIOUS,
                method=Method.HEURISTIC,
                signature="ELF-in-temp-directory",
                severity=Severity.MEDIUM,
                details="Native executable located in a transient/world-writable directory.",
                size=st.st_size,
            )
        )

    # 2. SUID / SGID binary outside the expected system locations.
    if mode & (stat.S_ISUID | stat.S_ISGID) and not spath.startswith(_EXPECTED_SUID_PREFIXES):
        bit = "SUID" if mode & stat.S_ISUID else "SGID"
        findings.append(
            Detection(
                path=spath,
                verdict=Verdict.SUSPICIOUS,
                method=Method.HEURISTIC,
                signature=f"unexpected-{bit.lower()}-binary",
                severity=Severity.HIGH,
                details=f"{bit} binary outside standard system paths — a common privilege-escalation foothold.",
                size=st.st_size,
            )
        )

    # 3. Hidden (dot-prefixed) executable that is an ELF binary.
    if path.name.startswith(".") and is_elf:
        findings.append(
            Detection(
                path=spath,
                verdict=Verdict.SUSPICIOUS,
                method=Method.HEURISTIC,
                signature="hidden-elf-binary",
                severity=Severity.MEDIUM,
                details="Executable disguised as a hidden dotfile.",
                size=st.st_size,
            )
        )

    # 4. World-writable file that is also executable.
    if mode & stat.S_IWOTH and mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        findings.append(
            Detection(
                path=spath,
                verdict=Verdict.SUSPICIOUS,
                method=Method.HEURISTIC,
                signature="world-writable-executable",
                severity=Severity.MEDIUM,
                details="Executable is writable by any user; trivially trojanisable.",
                size=st.st_size,
            )
        )

    # 5. Content patterns — only for files that can actually execute as code:
    #    a shebang, the executable bit, or a recognised script extension. This
    #    keeps documentation (.md/.txt) and markup (.html) from being flagged
    #    for merely *describing* a command.
    is_executable = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    has_script_ext = path.suffix.lower() in _SCRIPT_EXTS
    looks_runnable = is_script or is_executable or has_script_ext

    if looks_runnable and not is_elf and head and _looks_textual(head):
        for pattern, name, severity in _TEXT_PATTERNS:
            if pattern.search(head):
                findings.append(
                    Detection(
                        path=spath,
                        verdict=Verdict.SUSPICIOUS,
                        method=Method.HEURISTIC,
                        signature=name,
                        severity=severity,
                        details="Suspicious code pattern matched by heuristic scanner.",
                        size=st.st_size,
                    )
                )

    return findings


def _looks_textual(head: bytes) -> bool:
    """Cheap binary/text discriminator: reject content with NUL bytes."""
    if b"\x00" in head:
        return False
    # Mostly-printable check on a sample.
    sample = head[:4096]
    if not sample:
        return False
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(sample) > 0.85
