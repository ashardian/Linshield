"""Signature management: known-bad hashes and YARA rules.

Two complementary signal sources:

* **Hash database** — a JSON map of ``sha256 -> {name, severity}``. Fast, exact,
  zero false positives. Seeded with the EICAR test file so detection can be
  verified immediately. Populate it from threat-intel feeds over time.
* **YARA** — pattern matching over file content. The bundled rules ship with
  the package; user rules dropped into the data directory are compiled too.
  YARA is optional: if ``yara-python`` is missing the engine degrades cleanly.
"""

from __future__ import annotations

# LS-SELF-EXCLUDE-7f3a9c2e1b — LinShield-owned file; excluded from self-scanning.

import json
import logging
import re
from importlib import resources
from pathlib import Path

from .config import Paths
from .hashing import sha256_bytes
from .models import Severity

logger = logging.getLogger(__name__)

try:  # YARA is an optional dependency.
    import yara  # type: ignore

    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on environment
    yara = None  # type: ignore
    _YARA_AVAILABLE = False


# EICAR test file content -> its SHA-256, so we can seed the hash DB without
# shipping the string twice. This is the canonical harmless AV test artefact.
_EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode("ascii")


def _default_hashes() -> dict[str, dict[str, str]]:
    return {
        sha256_bytes(_EICAR): {
            "name": "EICAR-Test-Signature",
            "severity": Severity.LOW.value,
        }
    }


class SignatureStore:
    """Holds the loaded hash DB and compiled YARA rules."""

    def __init__(self, paths: Paths) -> None:
        self.paths = paths
        self.hashes: dict[str, dict[str, str]] = {}
        self._rules: object | None = None
        self._load_hashes()
        self._compile_yara()

    # -- hashes ------------------------------------------------------------
    def _load_hashes(self) -> None:
        path = self.paths.hash_db
        if path.exists():
            try:
                self.hashes = json.loads(path.read_text(encoding="utf-8"))
                return
            except (json.JSONDecodeError, OSError):
                pass
        self.hashes = _default_hashes()
        self._save_hashes()

    def _save_hashes(self) -> None:
        self.paths.hash_db.parent.mkdir(parents=True, exist_ok=True)
        self.paths.hash_db.write_text(
            json.dumps(self.hashes, indent=2, sort_keys=True), encoding="utf-8"
        )

    def add_hash(self, sha256: str, name: str, severity: Severity) -> None:
        self.hashes[sha256.lower()] = {"name": name, "severity": severity.value}
        self._save_hashes()

    def add_hashes_bulk(self, items: list[tuple[str, str, Severity]]) -> int:
        """Add many hashes in one write. Returns the number of new entries."""
        added = 0
        for sha256, name, severity in items:
            key = sha256.lower()
            if key not in self.hashes:
                added += 1
            self.hashes[key] = {"name": name, "severity": severity.value}
        if added or items:
            self._save_hashes()
        return added

    def match_hash(self, sha256: str) -> dict[str, str] | None:
        return self.hashes.get(sha256.lower())

    @property
    def hash_count(self) -> int:
        return len(self.hashes)

    # -- yara --------------------------------------------------------------
    def _yara_sources(self) -> dict[str, str]:
        """Collect rule namespaces from the bundled package and user dir."""
        sources: dict[str, str] = {}
        try:
            builtin = resources.files("linshield.data.yara").joinpath("builtin.yar")
            sources["builtin"] = builtin.read_text(encoding="utf-8")
        except (FileNotFoundError, ModuleNotFoundError, OSError):
            pass
        user_dir = self.paths.yara_user_dir
        if user_dir.is_dir():
            # Recurse so community rule packs installed under community/<src>/
            # are discovered too. Each file becomes its own namespace, keyed by
            # its path relative to the user dir.
            rule_files = sorted(user_dir.rglob("*.yar")) + sorted(
                user_dir.rglob("*.yara")
            )
            for rule_file in rule_files:
                try:
                    rel = rule_file.relative_to(user_dir).with_suffix("")
                    ns = "user_" + re.sub(r"[^0-9A-Za-z]+", "_", str(rel)).strip("_")
                    sources[ns] = rule_file.read_text(encoding="utf-8")
                except OSError:
                    continue
        return sources

    def _compile_yara(self) -> None:
        if not _YARA_AVAILABLE:
            self._rules = None
            return
        sources = self._yara_sources()
        if not sources:
            self._rules = None
            return
        try:
            self._rules = yara.compile(sources=sources)  # type: ignore[union-attr]
            return
        except yara.Error:  # type: ignore[union-attr]
            pass
        # One or more namespaces failed to compile together. Keep every
        # namespace that compiles on its own so a single bad rule pack can't
        # disable the whole engine (important with large community sets).
        good: dict[str, str] = {}
        for ns, text in sources.items():
            try:
                yara.compile(source=text)  # type: ignore[union-attr]
                good[ns] = text
            except yara.Error:  # type: ignore[union-attr]
                logger.warning("Skipping YARA namespace '%s' (compile error)", ns)
        try:
            self._rules = yara.compile(sources=good) if good else None  # type: ignore[union-attr]
        except yara.Error:  # type: ignore[union-attr]
            try:
                self._rules = yara.compile(  # type: ignore[union-attr]
                    sources={"builtin": sources.get("builtin", "")}
                )
            except yara.Error:  # type: ignore[union-attr]
                self._rules = None

    @property
    def yara_available(self) -> bool:
        return _YARA_AVAILABLE and self._rules is not None

    @property
    def yara_rule_count(self) -> int:
        if self._rules is None:
            return 0
        # python-yara exposes no public count; count rule declarations from
        # source, excluding internal `private` helper rules.
        decl = re.compile(
            r"^[ \t]*((?:private[ \t]+|global[ \t]+)*)rule[ \t]+\w+", re.MULTILINE
        )
        count = 0
        for src in self._yara_sources().values():
            for modifiers in decl.findall(src):
                if "private" not in modifiers:
                    count += 1
        return count

    def match_yara(self, path: Path) -> list[tuple[str, str, str]]:
        """Return ``(rule_name, severity, verdict)`` tuples that match the file.

        ``verdict`` is taken from each rule's ``meta: verdict`` field and is one
        of ``"infected"`` or ``"suspicious"``; it defaults to ``"infected"`` for
        rules that don't declare it.
        """
        if self._rules is None:
            return []
        try:
            matches = self._rules.match(str(path), timeout=30)  # type: ignore[union-attr]
        except yara.Error:  # type: ignore[union-attr]
            return []
        return self._matches_to_tuples(matches)

    def match_yara_bytes(self, data: bytes) -> list[tuple[str, str, str]]:
        """Like :meth:`match_yara` but scans an in-memory buffer (archive members)."""
        if self._rules is None:
            return []
        try:
            matches = self._rules.match(data=data, timeout=30)  # type: ignore[union-attr]
        except yara.Error:  # type: ignore[union-attr]
            return []
        return self._matches_to_tuples(matches)

    @staticmethod
    def _matches_to_tuples(matches: object) -> list[tuple[str, str, str]]:
        results: list[tuple[str, str, str]] = []
        for match in matches:  # type: ignore[attr-defined]
            severity = str(match.meta.get("severity", Severity.MEDIUM.value))
            verdict = str(match.meta.get("verdict", "infected")).lower()
            results.append((match.rule, severity, verdict))
        return results

    def reload(self) -> None:
        self._load_hashes()
        self._compile_yara()


def severity_from_str(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.MEDIUM
