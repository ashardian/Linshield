"""Optional ClamAV integration.

If the host has ClamAV installed, LinShield uses it as a first-class signature
engine — ClamAV ships millions of curated, frequently-updated signatures via
``freshclam``. We prefer the resident daemon (``clamdscan``) for speed and fall
back to the standalone scanner (``clamscan``). Absence of ClamAV is fine; the
other engines still run.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .models import Detection, Method, Severity, Verdict


class ClamAV:
    """Wrapper around the ClamAV command-line scanners."""

    def __init__(self) -> None:
        self.clamdscan = shutil.which("clamdscan")
        self.clamscan = shutil.which("clamscan")

    @property
    def available(self) -> bool:
        return bool(self.clamdscan or self.clamscan)

    @property
    def engine_name(self) -> str:
        if self.clamdscan:
            return "clamdscan (daemon)"
        if self.clamscan:
            return "clamscan"
        return "unavailable"

    def scan_file(self, path: Path) -> Detection | None:
        """Scan a single file. Returns a Detection only on a positive hit."""
        if not self.available:
            return None
        if self.clamdscan:
            cmd = [self.clamdscan, "--no-summary", "--fdpass", str(path)]
        else:
            cmd = [self.clamscan, "--no-summary", "--stdout", str(path)]
        try:
            proc = subprocess.run(  # noqa: S603 - fixed, trusted argv
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            return None

        # ClamAV exit code 1 == virus found, 0 == clean, 2 == error.
        if proc.returncode != 1:
            return None
        signature = self._parse_signature(proc.stdout)
        return Detection(
            path=str(path),
            verdict=Verdict.INFECTED,
            method=Method.CLAMAV,
            signature=signature or "ClamAV.Detected",
            severity=Severity.HIGH,
            details="Matched a ClamAV signature.",
        )

    @staticmethod
    def _parse_signature(output: str) -> str | None:
        # Output line format: "/path/to/file: Signature.Name FOUND"
        for line in output.splitlines():
            if line.strip().endswith("FOUND"):
                body = line.rsplit(":", 1)[-1].strip()
                return body.removesuffix("FOUND").strip()
        return None
