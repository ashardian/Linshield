"""Confidence scoring — turn raw per-engine findings into honest tiers.

The detection engines disagree in trustworthiness:

- A SHA-256 **hash** match or a **ClamAV** hit is definitive.
- A **YARA** match is a pattern match: specific rules (reverse shells, miners)
  are fairly reliable; broad "suspicious" idioms (``curl | bash``) are not.
- A **heuristic** is a hint, not proof.

A single fuzzy pattern hit must therefore never be presented as a definitive
"INFECTED" conviction. This module aggregates all of a file's findings and
assigns a :class:`Confidence` tier, requiring *corroboration* (independent
engines agreeing, or several strong rules) before escalating. This is what
keeps false positives from causing panic: lone pattern hits land in the calm
REVIEW tier, not the red CONFIRMED one.
"""

from __future__ import annotations

from collections import defaultdict

from .models import Confidence, Detection, Method, Severity, Verdict


def _detection_points(det: Detection) -> float:
    """Weight a single finding by how much trust its engine/verdict earns."""
    if det.method in (Method.HASH, Method.CLAMAV):
        return 100.0  # definitive — handled explicitly, but scored high anyway
    if det.method is Method.YARA:
        base = 3.0 if det.verdict is Verdict.INFECTED else 1.0
    else:  # HEURISTIC
        base = 1.0
    # A little extra weight for severe findings, but never enough for a single
    # medium/low pattern hit to escape the REVIEW tier on its own.
    if det.severity is Severity.CRITICAL:
        base += 1.0
    elif det.severity is Severity.HIGH:
        base += 0.5
    return base


def assess(detections: list[Detection]) -> Confidence:
    """Assess the confidence tier for the findings belonging to ONE file."""
    if not detections:
        return Confidence.CLEAN

    # Definitive engines win outright.
    if any(d.method in (Method.HASH, Method.CLAMAV) for d in detections):
        return Confidence.CONFIRMED

    methods = {d.method for d in detections}
    yara_infected = sum(
        1 for d in detections if d.method is Method.YARA and d.verdict is Verdict.INFECTED
    )
    critical_yara = any(
        d.method is Method.YARA
        and d.verdict is Verdict.INFECTED
        and d.severity is Severity.CRITICAL
        for d in detections
    )
    distinct_sigs = {d.signature for d in detections}
    points = sum(_detection_points(d) for d in detections)

    # Corroboration: independent engines agreeing, several strong rules, or a
    # single high-specificity (critical) rule promote a file to LIKELY.
    # Nothing pattern-based ever reaches CONFIRMED.
    corroborated = (
        (Method.YARA in methods and Method.HEURISTIC in methods and points >= 4.0)
        or yara_infected >= 2
        or (yara_infected >= 1 and len(distinct_sigs) >= 2)
        or critical_yara
    )
    if corroborated:
        return Confidence.LIKELY

    # Everything else is a single / weak signal: calm, informational.
    return Confidence.REVIEW


def annotate(summary: object) -> None:
    """Group a scan's detections by file, assess each, and tag every detection.

    Sets ``detection.confidence`` on every detection in ``summary.detections``
    so the CLI/GUI can present the per-file tier consistently.
    """
    by_path: dict[str, list[Detection]] = defaultdict(list)
    for det in summary.detections:  # type: ignore[attr-defined]
        # Archive members share the tier of their containing file.
        key = det.path.split("!", 1)[0]
        by_path[key].append(det)

    for key, dets in by_path.items():
        tier = assess(dets)
        for det in dets:
            det.confidence = tier


def annotate_one(detections: list[Detection]) -> None:
    """Tag a single file's detection list with its assessed tier (in place)."""
    tier = assess(detections)
    for det in detections:
        det.confidence = tier


def quarantine_worthy(detections: list[Detection]) -> bool:
    """Only CONFIRMED-tier files should ever be auto-quarantined."""
    return assess(detections) is Confidence.CONFIRMED
