"""LinShield core: the engine, models and subsystems."""

from __future__ import annotations

from .config import Config, Paths, load_config, save_config
from .engine import Engine, setup_logging
from .models import (
    Detection,
    Finding,
    Method,
    QuarantineEntry,
    ScanSummary,
    Severity,
    Verdict,
)

__all__ = [
    "Engine",
    "setup_logging",
    "Config",
    "Paths",
    "load_config",
    "save_config",
    "Detection",
    "Finding",
    "Method",
    "QuarantineEntry",
    "ScanSummary",
    "Severity",
    "Verdict",
]
