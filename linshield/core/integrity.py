"""File-integrity monitoring (FIM).

Take a cryptographic baseline of critical system files (the binaries and
config most often tampered with after a compromise) and later diff against it
to surface additions, deletions and modifications. This is an AIDE-style lite
check that lives entirely inside LinShield's database.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable, Iterator
from pathlib import Path

from .database import Database
from .hashing import sha256_file
from .models import Finding, Severity

_MAX_FIM_FILE = 200 * 1024 * 1024  # skip very large files in the baseline


def _iter_targets(paths: Iterable[str]) -> Iterator[Path]:
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            yield p
        elif p.is_dir():
            for dirpath, _dirs, files in os.walk(p):
                for name in files:
                    yield Path(dirpath) / name


def build_baseline(db: Database, fim_paths: Iterable[str]) -> int:
    """Hash all FIM targets and store them as the new baseline.

    Returns:
        Number of files recorded.
    """
    records: list[tuple[str, str, int, int, float, int, int]] = []
    for path in _iter_targets(fim_paths):
        try:
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_FIM_FILE:
                continue
            digest = sha256_file(path)
        except OSError:
            continue
        records.append(
            (str(path), digest, st.st_size, st.st_mode & 0o7777,
             st.st_mtime, st.st_uid, st.st_gid)
        )
    db.set_baseline(records)
    return len(records)


def check_integrity(db: Database, fim_paths: Iterable[str]) -> list[Finding]:
    """Diff the current state against the stored baseline."""
    baseline = db.get_baseline()
    if not baseline:
        return [
            Finding(
                category="integrity",
                title="No integrity baseline exists yet",
                severity=Severity.INFO,
                detail="Run the FIM 'init' command to capture a baseline first.",
            )
        ]

    findings: list[Finding] = []
    current_paths: set[str] = set()

    for path in _iter_targets(fim_paths):
        spath = str(path)
        current_paths.add(spath)
        try:
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_FIM_FILE:
                continue
            digest = sha256_file(path)
        except OSError:
            continue

        base = baseline.get(spath)
        if base is None:
            findings.append(
                Finding(
                    category="integrity",
                    title=f"New file appeared: {spath}",
                    severity=Severity.MEDIUM,
                    detail="File present now but absent from the baseline.",
                )
            )
            continue
        if digest != base.get("sha256"):
            findings.append(
                Finding(
                    category="integrity",
                    title=f"Content changed: {spath}",
                    severity=Severity.HIGH,
                    detail=(
                        f"SHA-256 differs from baseline "
                        f"({str(base.get('sha256'))[:12]}… → {digest[:12]}…)."
                    ),
                )
            )
        elif (st.st_mode & 0o7777) != int(base.get("mode", 0)):
            findings.append(
                Finding(
                    category="integrity",
                    title=f"Permissions changed: {spath}",
                    severity=Severity.MEDIUM,
                    detail=(
                        f"Mode {oct(int(base.get('mode', 0)))} → "
                        f"{oct(st.st_mode & 0o7777)}."
                    ),
                )
            )
        elif (
            int(base.get("uid", -1)) != -1
            and (st.st_uid != int(base.get("uid", -1)) or st.st_gid != int(base.get("gid", -1)))
        ):
            findings.append(
                Finding(
                    category="integrity",
                    title=f"Ownership changed: {spath}",
                    severity=Severity.HIGH,
                    detail=(
                        f"Owner {base.get('uid')}:{base.get('gid')} → "
                        f"{st.st_uid}:{st.st_gid}. A changed owner on a system "
                        f"file is a common post-compromise indicator."
                    ),
                )
            )

    for missing in set(baseline) - current_paths:
        findings.append(
            Finding(
                category="integrity",
                title=f"Baselined file is missing: {missing}",
                severity=Severity.HIGH,
                detail="File was in the baseline but is no longer present.",
            )
        )

    if not findings:
        findings.append(
            Finding(
                category="integrity",
                title="Integrity intact",
                severity=Severity.INFO,
                detail=f"All {len(baseline)} baselined files are unchanged.",
            )
        )
    return findings
