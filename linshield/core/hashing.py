"""Hashing helpers used by the scanner, signature DB and integrity monitor."""

from __future__ import annotations

import hashlib
from pathlib import Path

_CHUNK = 1024 * 1024  # 1 MiB


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of a file, read in 1 MiB chunks.

    Raises:
        OSError: If the file cannot be read.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def md5_file(path: Path) -> str:
    """Return the hex MD5 of a file (used only for ClamAV-style compatibility)."""
    digest = hashlib.md5()  # noqa: S324 - not used for security decisions
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
