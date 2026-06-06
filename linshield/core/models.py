"""Shared data models for LinShield.

These dataclasses and enums are the common vocabulary used by the scanner,
quarantine manager, database layer, CLI and GUI. Keeping them in one place
means the CLI and GUI render exactly the same objects the engine produces.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    """The outcome of inspecting a single file."""

    CLEAN = "clean"
    INFECTED = "infected"
    SUSPICIOUS = "suspicious"
    ERROR = "error"
    SKIPPED = "skipped"


class Method(str, Enum):
    """Which detection engine produced a finding."""

    HASH = "hash"
    YARA = "yara"
    CLAMAV = "clamav"
    HEURISTIC = "heuristic"


class Severity(str, Enum):
    """Relative danger of a finding, used for sorting and UI colour."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]


class Confidence(str, Enum):
    """How sure LinShield is that a file is actually malicious.

    This is the user-facing tier, computed by corroborating engine signals.
    It exists so a single fuzzy pattern match is never dressed up as a
    definitive conviction:

    - CONFIRMED: a definitive signal (exact hash match or ClamAV), or strong
      corroboration. Safe to act on / auto-quarantine.
    - LIKELY: multiple independent signals agree, but none is definitive.
      Worth investigating.
    - REVIEW: a single pattern/heuristic hit. Frequently a false positive,
      especially on security tools, installers and source code. Informational.
    - CLEAN: nothing flagged.
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    REVIEW = "review"
    CLEAN = "clean"

    @property
    def rank(self) -> int:
        return {
            Confidence.CLEAN: 0,
            Confidence.REVIEW: 1,
            Confidence.LIKELY: 2,
            Confidence.CONFIRMED: 3,
        }[self]


@dataclass(slots=True)
class Detection:
    """A single positive finding against a file."""

    path: str
    verdict: Verdict
    method: Method
    signature: str
    severity: Severity = Severity.MEDIUM
    details: str = ""
    sha256: str = ""
    size: int = 0
    timestamp: float = field(default_factory=time.time)
    # Per-file aggregate tier, filled in after a scan by confidence.annotate().
    confidence: "Confidence | None" = None

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "verdict": self.verdict.value,
            "method": self.method.value,
            "signature": self.signature,
            "severity": self.severity.value,
            "details": self.details,
            "sha256": self.sha256,
            "size": self.size,
            "timestamp": self.timestamp,
            "confidence": self.confidence.value if self.confidence else None,
        }


@dataclass(slots=True)
class ScanSummary:
    """Aggregate result of scanning one or more paths."""

    scan_type: str = "custom"
    started: float = field(default_factory=time.time)
    ended: float = 0.0
    files_scanned: int = 0
    bytes_scanned: int = 0
    errors: int = 0
    detections: list[Detection] = field(default_factory=list)
    auto_quarantined: int = 0

    @property
    def duration(self) -> float:
        return (self.ended or time.time()) - self.started

    @property
    def infected(self) -> int:
        return sum(1 for d in self.detections if d.verdict is Verdict.INFECTED)

    @property
    def suspicious(self) -> int:
        return sum(1 for d in self.detections if d.verdict is Verdict.SUSPICIOUS)

    @property
    def is_clean(self) -> bool:
        return not self.detections

    def _files_at(self, tier: "Confidence") -> int:
        return len({d.path for d in self.detections if d.confidence is tier})

    @property
    def confirmed(self) -> int:
        return self._files_at(Confidence.CONFIRMED)

    @property
    def likely(self) -> int:
        return self._files_at(Confidence.LIKELY)

    @property
    def review(self) -> int:
        return self._files_at(Confidence.REVIEW)

    def top_severity(self) -> Severity:
        if not self.detections:
            return Severity.INFO
        return max((d.severity for d in self.detections), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, object]:
        return {
            "scan_type": self.scan_type,
            "started": self.started,
            "ended": self.ended,
            "duration": round(self.duration, 3),
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "errors": self.errors,
            "infected": self.infected,
            "suspicious": self.suspicious,
            "confirmed": self.confirmed,
            "likely": self.likely,
            "review": self.review,
            "auto_quarantined": self.auto_quarantined,
            "top_severity": self.top_severity().value,
            "detections": [d.to_dict() for d in self.detections],
        }


@dataclass(slots=True)
class QuarantineEntry:
    """A file that has been isolated in the quarantine vault."""

    qid: int
    original_path: str
    stored_name: str
    sha256: str
    size: int
    signature: str
    severity: str
    quarantined_at: float
    original_mode: int

    def to_dict(self) -> dict[str, object]:
        return {
            "qid": self.qid,
            "original_path": self.original_path,
            "stored_name": self.stored_name,
            "sha256": self.sha256,
            "size": self.size,
            "signature": self.signature,
            "severity": self.severity,
            "quarantined_at": self.quarantined_at,
            "original_mode": self.original_mode,
        }


@dataclass(slots=True)
class Finding:
    """A non-file security finding (rootkit check, FIM diff, firewall, etc.)."""

    category: str
    title: str
    severity: Severity
    detail: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "title": self.title,
            "severity": self.severity.value,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }
