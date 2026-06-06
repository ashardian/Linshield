"""Quarantine vault.

Detected files are moved into a private, mode-0700 vault, renamed to an
opaque hash-based name, and neutralised (``chmod 000``) so they cannot be
executed or read in place. The original path, permissions and metadata are
recorded so the file can be restored verbatim if it turns out to be a false
positive.
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from .config import Paths
from .database import Database
from .hashing import sha256_file
from .models import Detection, QuarantineEntry


class QuarantineError(Exception):
    """Raised when an isolate/restore operation cannot complete safely."""


class Quarantine:
    """Manages the on-disk quarantine vault and its database records."""

    def __init__(self, paths: Paths, db: Database) -> None:
        self.paths = paths
        self.db = db
        self.vault = paths.quarantine_dir
        self.vault.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.vault, 0o700)
        except PermissionError:
            pass

    def isolate(self, detection: Detection) -> QuarantineEntry:
        """Move the file referenced by ``detection`` into the vault.

        Raises:
            QuarantineError: If the source is missing or cannot be moved.
        """
        src = Path(detection.path)
        if not src.exists():
            raise QuarantineError(f"Source no longer exists: {src}")

        try:
            st = src.stat()
            digest = detection.sha256 or sha256_file(src)
        except OSError as exc:
            raise QuarantineError(f"Cannot read source: {exc}") from exc

        stored_name = f"{int(time.time()*1000):x}_{digest[:16]}.quar"
        dest = self.vault / stored_name

        try:
            shutil.move(str(src), str(dest))
        except OSError as exc:
            raise QuarantineError(f"Failed to move file: {exc}") from exc

        # Neutralise: strip all permission bits so the sample is inert.
        try:
            os.chmod(dest, 0o000)
        except OSError:
            pass

        entry = QuarantineEntry(
            qid=0,
            original_path=str(src),
            stored_name=stored_name,
            sha256=digest,
            size=st.st_size,
            signature=detection.signature,
            severity=detection.severity.value,
            quarantined_at=time.time(),
            original_mode=stat_mode(st.st_mode),
        )
        entry.qid = self.db.add_quarantine(entry)
        return entry

    def restore(self, qid: int) -> Path:
        """Restore a quarantined file to its original path and permissions."""
        entry = self.db.get_quarantine(qid)
        if entry is None:
            raise QuarantineError(f"No quarantine entry with id {qid}")
        stored = self.vault / entry.stored_name
        if not stored.exists():
            raise QuarantineError("Quarantined payload missing from vault")

        target = Path(entry.original_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(stored, 0o600)
            shutil.move(str(stored), str(target))
            os.chmod(target, entry.original_mode or 0o600)
        except OSError as exc:
            raise QuarantineError(f"Restore failed: {exc}") from exc
        self.db.mark_restored(qid)
        return target

    def delete(self, qid: int) -> None:
        """Permanently delete a quarantined sample from disk and the DB."""
        entry = self.db.get_quarantine(qid)
        if entry is None:
            raise QuarantineError(f"No quarantine entry with id {qid}")
        stored = self.vault / entry.stored_name
        if stored.exists():
            try:
                os.chmod(stored, 0o600)
                stored.unlink()
            except OSError as exc:
                raise QuarantineError(f"Delete failed: {exc}") from exc
        self.db.delete_quarantine(qid)

    def list(self, include_restored: bool = False) -> list[QuarantineEntry]:
        return self.db.list_quarantine(include_restored=include_restored)


def stat_mode(mode: int) -> int:
    """Extract just the permission bits from a stat mode."""
    return mode & 0o7777
