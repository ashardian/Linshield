"""The on-demand scanning engine.

Given a path, the scanner walks it (respecting excludes, size limits and
symlink policy), then for each regular file applies the enabled detection
engines in cheapest-first order: hash lookup, YARA, ClamAV, heuristics.
A single positive INFECTED result short-circuits the slower engines, while
heuristics always run so SUSPICIOUS hints are not masked by a clean verdict.
"""

from __future__ import annotations

# LS-SELF-EXCLUDE-7f3a9c2e1b — LinShield-owned file; excluded from self-scanning.

import fnmatch
import os
import stat
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from . import heuristics
from .clamav import ClamAV
from .config import Config
from .hashing import sha256_file
from .models import Detection, Method, ScanSummary, Severity, Verdict
from .signatures import SignatureStore, severity_from_str

ProgressCallback = Callable[[int, str], None]


class ScanCancelled(Exception):
    """Raised internally to abort a walk when the cancel flag is set."""


class Scanner:
    """Applies all enabled detection engines to files and directories."""

    def __init__(self, config: Config, signatures: SignatureStore) -> None:
        self.config = config
        self.signatures = signatures
        self.clamav = ClamAV()
        self._max_bytes = config.max_file_size_mb * 1024 * 1024
        # LinShield's own storage must never be scanned: it holds the signature
        # databases, downloaded rule packs, the quarantine vault and the DB,
        # all of which legitimately contain malware indicators as data and would
        # otherwise self-flag. The XDG data dir is not in the default excludes,
        # so resolve and exclude these explicitly regardless of root/user mode.
        p = signatures.paths
        own: set[str] = set()
        for d in (p.data_dir, p.config_dir, p.quarantine_dir, p.yara_user_dir):
            try:
                own.add(os.path.normpath(str(d)))
            except (TypeError, ValueError):
                continue
        self._own_dirs = tuple(own)

    # -- public API --------------------------------------------------------
    def scan_paths(
        self,
        roots: Iterable[str | Path],
        *,
        scan_type: str = "custom",
        recursive: bool = True,
        progress: ProgressCallback | None = None,
        cancel: threading.Event | None = None,
    ) -> ScanSummary:
        """Scan a collection of files/directories and return a summary."""
        summary = ScanSummary(scan_type=scan_type)
        try:
            for path in self._iter_files(roots, recursive=recursive, cancel=cancel):
                if cancel is not None and cancel.is_set():
                    raise ScanCancelled
                self._scan_one(path, summary, progress)
        except ScanCancelled:
            summary.scan_type = f"{scan_type} (cancelled)"
        summary.ended = time.time()
        return summary

    def scan_file(self, path: Path) -> list[Detection]:
        """Scan exactly one file (used by the real-time monitor)."""
        summary = ScanSummary(scan_type="realtime")
        self._scan_one(path, summary, None)
        return summary.detections

    # -- walking -----------------------------------------------------------
    def _iter_files(
        self,
        roots: Iterable[str | Path],
        *,
        recursive: bool,
        cancel: threading.Event | None,
    ) -> Iterator[Path]:
        seen: set[str] = set()
        for root in roots:
            root_path = Path(root)
            if self._excluded(str(root_path)):
                continue
            if root_path.is_file():
                yield root_path
                continue
            if not root_path.is_dir():
                continue
            if not recursive:
                for child in self._safe_listdir(root_path):
                    if child.is_file() and not self._excluded(str(child)):
                        yield child
                continue
            for dirpath, dirnames, filenames in os.walk(
                root_path, followlinks=self.config.follow_symlinks
            ):
                if cancel is not None and cancel.is_set():
                    raise ScanCancelled
                # Prune excluded subtrees in place for efficiency.
                dirnames[:] = [
                    d for d in dirnames if not self._excluded(os.path.join(dirpath, d))
                ]
                real = os.path.realpath(dirpath)
                if real in seen:  # guard against symlink loops
                    dirnames[:] = []
                    continue
                seen.add(real)
                for name in filenames:
                    full = os.path.join(dirpath, name)
                    if not self._excluded(full):
                        yield Path(full)

    @staticmethod
    def _safe_listdir(path: Path) -> list[Path]:
        try:
            return list(path.iterdir())
        except OSError:
            return []

    def _excluded(self, path: str) -> bool:
        norm = os.path.normpath(path)
        for own in self._own_dirs:
            if norm == own or norm.startswith(own + os.sep):
                return True
        # User-defined trust allowlist: never scan/flag these paths.
        for trusted in self.config.trusted_paths:
            t = os.path.normpath(os.path.expanduser(trusted))
            if norm == t or norm.startswith(t + os.sep):
                return True
            if fnmatch.fnmatch(path, trusted) or fnmatch.fnmatch(
                os.path.basename(path), trusted
            ):
                return True
        for pattern in self.config.exclude:
            if pattern.startswith("/"):
                if path == pattern or path.startswith(pattern.rstrip("/") + "/"):
                    return True
            elif fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(
                os.path.basename(path), pattern
            ):
                return True
        return False

    # -- per-file scanning -------------------------------------------------
    def _scan_one(
        self,
        path: Path,
        summary: ScanSummary,
        progress: ProgressCallback | None,
    ) -> None:
        try:
            st = path.lstat()
        except OSError:
            summary.errors += 1
            return

        # Skip symlinks (unless told to follow) and all non-regular files.
        if stat.S_ISLNK(st.st_mode):
            if not self.config.follow_symlinks:
                return
            try:
                st = path.stat()
            except OSError:
                summary.errors += 1
                return
        if not stat.S_ISREG(st.st_mode):
            return
        if st.st_size > self._max_bytes:
            return  # too large; out of policy
        if self._excluded(str(path)):
            return  # LinShield's own storage / configured exclusions

        summary.files_scanned += 1
        summary.bytes_scanned += st.st_size
        if progress is not None:
            progress(summary.files_scanned, str(path))

        head: bytes | None = None
        infected_found = False

        # 1. Hash lookup (exact, cheapest definitive signal).
        digest = ""
        if self.config.use_hashes:
            try:
                digest = sha256_file(path)
            except OSError:
                summary.errors += 1
            else:
                hit = self.signatures.match_hash(digest)
                if hit is not None:
                    summary.detections.append(
                        Detection(
                            path=str(path),
                            verdict=Verdict.INFECTED,
                            method=Method.HASH,
                            signature=hit.get("name", "Known-Bad-Hash"),
                            severity=severity_from_str(hit.get("severity", "high")),
                            details="File SHA-256 matched a known-malicious hash.",
                            sha256=digest,
                            size=st.st_size,
                        )
                    )
                    infected_found = True

        # 2. YARA pattern matching. Rule files (.yar/.yara) are signature DATA
        # that necessarily contain malware indicators, so scanning them with
        # YARA produces guaranteed false positives — skip the engine for them.
        is_rule_file = path.suffix.lower() in (".yar", ".yara")
        if (
            self.config.use_yara
            and not infected_found
            and not is_rule_file
            and self.signatures.yara_available
        ):
            for rule, sev, verdict in self.signatures.match_yara(path):
                is_infected = verdict != "suspicious"
                summary.detections.append(
                    Detection(
                        path=str(path),
                        verdict=Verdict.INFECTED if is_infected else Verdict.SUSPICIOUS,
                        method=Method.YARA,
                        signature=rule,
                        severity=severity_from_str(sev),
                        details="Matched a YARA rule.",
                        sha256=digest,
                        size=st.st_size,
                    )
                )
                if is_infected:
                    infected_found = True

        # 3. ClamAV (only if nothing definitive yet, to save time).
        if self.config.use_clamav and not infected_found and self.clamav.available:
            det = self.clamav.scan_file(path)
            if det is not None:
                det.sha256 = digest
                det.size = st.st_size
                summary.detections.append(det)
                infected_found = True

        # 4. Heuristics always run — they surface different (SUSPICIOUS) info.
        if self.config.use_heuristics:
            head = self._read_head(path)
            for det in heuristics.inspect(path, st, head):
                det.sha256 = digest
                summary.detections.append(det)

        # 5. Archive inspection (opt-in): look inside zip/tar containers so
        # malware shipped inside an archive is caught without manual extraction.
        if self.config.scan_archives and not is_rule_file:
            self._scan_archive(path, summary)

    # -- archive scanning --------------------------------------------------
    _ZIP_EXTS = (".zip", ".jar", ".apk", ".war", ".egg", ".whl")
    _TAR_EXTS = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
    _ARCHIVE_MEMBER_LIMIT = 2000
    _ARCHIVE_TOTAL_LIMIT = 1024 * 1024 * 1024  # 1 GiB uncompressed (zip-bomb guard)
    _MAX_ARCHIVE_DEPTH = 1  # recurse into one level of nested archives

    def _scan_archive(self, path: Path, summary: ScanSummary) -> None:
        import tarfile
        import zipfile

        name = path.name.lower()
        try:
            if name.endswith(self._ZIP_EXTS) or zipfile.is_zipfile(path):
                self._scan_zip(path, summary, depth=0)
            elif name.endswith(self._TAR_EXTS) or tarfile.is_tarfile(path):
                self._scan_tar(path, summary, depth=0)
        except (OSError, zipfile.BadZipFile, tarfile.TarError, EOFError, ValueError):
            return  # unreadable / corrupt archive — not a detection

    def _looks_archive(self, name: str, data: bytes) -> bool:
        lname = name.lower()
        if lname.endswith(self._ZIP_EXTS) or lname.endswith(self._TAR_EXTS):
            return True
        # Magic sniff: PK zip, gzip, bzip2, xz.
        return data[:2] in (b"PK", b"\x1f\x8b", b"BZ") or data[:6] == b"\xfd7zXZ\x00"

    def _scan_member(self, container: Path, member: str, data: bytes,
                     summary: ScanSummary, depth: int = 0) -> None:
        import io
        import tarfile
        import zipfile

        from .hashing import sha256_bytes

        # Rule files inside an archive are signature data — never YARA-scan them.
        if member.lower().endswith((".yar", ".yara")):
            return
        label = f"{container}!{member}"
        digest = sha256_bytes(data)
        hit = self.signatures.match_hash(digest)
        if hit is not None:
            summary.detections.append(Detection(
                path=label, verdict=Verdict.INFECTED, method=Method.HASH,
                signature=hit["name"], severity=severity_from_str(hit.get("severity", "high")),
                details="Known-bad hash inside archive.", sha256=digest, size=len(data),
            ))
            return  # definitive
        if self.config.use_yara and self.signatures.yara_available:
            for rule, sev, verdict in self.signatures.match_yara_bytes(data):
                is_inf = verdict != "suspicious"
                summary.detections.append(Detection(
                    path=label,
                    verdict=Verdict.INFECTED if is_inf else Verdict.SUSPICIOUS,
                    method=Method.YARA, signature=rule,
                    severity=severity_from_str(sev),
                    details="Matched a YARA rule inside archive.",
                    sha256=digest, size=len(data),
                ))

        # Nested archive (a .zip inside a .zip, etc.) — recurse one level.
        if depth < self._MAX_ARCHIVE_DEPTH and self._looks_archive(member, data):
            buf = io.BytesIO(data)
            try:
                if zipfile.is_zipfile(buf):
                    buf.seek(0)
                    self._scan_zip(buf, summary, depth=depth + 1, container=Path(label))
                else:
                    buf.seek(0)
                    if tarfile.is_tarfile(buf):  # type: ignore[arg-type]
                        buf.seek(0)
                        self._scan_tar(buf, summary, depth=depth + 1, container=Path(label))
            except (OSError, zipfile.BadZipFile, tarfile.TarError, EOFError, ValueError):
                return

    def _scan_zip(self, path: object, summary: ScanSummary, depth: int = 0,
                  container: Path | None = None) -> None:
        import zipfile

        cont = container if container is not None else Path(str(path))
        total = 0
        with zipfile.ZipFile(path) as zf:  # type: ignore[arg-type]
            for info in zf.infolist()[: self._ARCHIVE_MEMBER_LIMIT]:
                if info.is_dir() or info.file_size == 0:
                    continue
                if info.file_size > self._max_bytes:
                    continue
                total += info.file_size
                if total > self._ARCHIVE_TOTAL_LIMIT:
                    break
                try:
                    data = zf.read(info)
                except (OSError, zipfile.BadZipFile, RuntimeError):
                    continue
                self._scan_member(cont, info.filename, data, summary, depth=depth)

    def _scan_tar(self, path: object, summary: ScanSummary, depth: int = 0,
                  container: Path | None = None) -> None:
        import tarfile

        cont = container if container is not None else Path(str(path))
        total = 0
        count = 0
        opener = (
            tarfile.open(fileobj=path)  # type: ignore[arg-type]
            if hasattr(path, "read")
            else tarfile.open(path)  # type: ignore[arg-type]
        )
        with opener as tf:
            for member in tf:
                if count >= self._ARCHIVE_MEMBER_LIMIT:
                    break
                if not member.isfile() or member.size == 0:
                    continue
                if member.size > self._max_bytes:
                    continue
                total += member.size
                if total > self._ARCHIVE_TOTAL_LIMIT:
                    break
                count += 1
                try:
                    fh = tf.extractfile(member)
                    if fh is None:
                        continue
                    data = fh.read()
                except (OSError, tarfile.TarError):
                    continue
                self._scan_member(cont, member.name, data, summary, depth=depth)

    @staticmethod
    def _read_head(path: Path, n: int = 65536) -> bytes:
        try:
            with path.open("rb") as handle:
                return handle.read(n)
        except OSError:
            return b""

    # -- engine status -----------------------------------------------------
    def engine_status(self) -> dict[str, object]:
        return {
            "hashes": {
                "enabled": self.config.use_hashes,
                "count": self.signatures.hash_count,
            },
            "yara": {
                "enabled": self.config.use_yara,
                "available": self.signatures.yara_available,
                "rules": self.signatures.yara_rule_count,
            },
            "clamav": {
                "enabled": self.config.use_clamav,
                "available": self.clamav.available,
                "engine": self.clamav.engine_name,
            },
            "heuristics": {"enabled": self.config.use_heuristics},
        }
