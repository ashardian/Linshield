"""The LinShield engine facade.

A single object that wires together configuration, database, signatures,
scanner, quarantine, FIM, rootkit and firewall modules. Both the CLI and the
GUI talk to this facade, guaranteeing identical behaviour regardless of how
the user drives the tool.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterable
from pathlib import Path

from . import firewall, integrity, rootkit
from .config import Config, Paths, load_config, save_config
from .database import Database
from .models import Finding, ScanSummary, Severity
from .monitor import RealtimeMonitor
from .quarantine import Quarantine
from .scanner import ProgressCallback, Scanner
from .signatures import SignatureStore, severity_from_str

logger = logging.getLogger("linshield")


def setup_logging(paths: Paths, verbose: bool = False) -> None:
    """Configure root logging to file plus stderr."""
    paths.ensure()
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    try:
        handlers.append(logging.FileHandler(paths.log_file))
    except OSError:
        pass
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


class Engine:
    """Facade over every LinShield subsystem."""

    def __init__(self, paths: Paths | None = None) -> None:
        self.paths = paths or Paths.resolve()
        self.paths.ensure()
        self.config: Config = load_config(self.paths)
        self.db = Database(self.paths.database)
        self.signatures = SignatureStore(self.paths)
        self.scanner = Scanner(self.config, self.signatures)
        self.quarantine = Quarantine(self.paths, self.db)
        self._monitor: RealtimeMonitor | None = None

    # -- scanning ----------------------------------------------------------
    def scan(
        self,
        roots: Iterable[str | Path] | None = None,
        *,
        scan_type: str = "custom",
        recursive: bool = True,
        auto_quarantine: bool | None = None,
        progress: ProgressCallback | None = None,
        cancel: threading.Event | None = None,
        record: bool = True,
    ) -> ScanSummary:
        """Run a scan, optionally auto-quarantine, and persist the result."""
        if roots is None:
            roots = self.config.quick_scan_paths
        summary = self.scanner.scan_paths(
            roots,
            scan_type=scan_type,
            recursive=recursive,
            progress=progress,
            cancel=cancel,
        )
        # Assign each file a corroboration-based confidence tier before anything
        # acts on the results.
        from . import confidence

        confidence.annotate(summary)
        do_quarantine = (
            self.config.auto_quarantine if auto_quarantine is None else auto_quarantine
        )
        if do_quarantine:
            summary.auto_quarantined = self._quarantine_infected(summary)
        if record:
            self.db.record_scan(summary)
        return summary

    def quick_scan(self, **kw: object) -> ScanSummary:
        return self.scan(self.config.quick_scan_paths, scan_type="quick", **kw)  # type: ignore[arg-type]

    def full_scan(self, **kw: object) -> ScanSummary:
        return self.scan(self.config.full_scan_roots, scan_type="full", **kw)  # type: ignore[arg-type]

    def _quarantine_infected(self, summary: ScanSummary) -> int:
        from .models import Confidence

        # Auto-quarantine ONLY definitive (CONFIRMED) detections. Pattern-based
        # LIKELY/REVIEW findings are never auto-actioned — they could be false
        # positives, and silently quarantining a user's files would be worse
        # than the threat for a triage tool.
        count = 0
        seen: set[str] = set()
        for det in summary.detections:
            if det.confidence is not Confidence.CONFIRMED:
                continue
            if det.path in seen:
                continue
            seen.add(det.path)
            try:
                self.quarantine.isolate(det)
                count += 1
            except Exception as exc:  # noqa: BLE001
                logger.error("Quarantine of %s failed: %s", det.path, exc)
        return count

    # -- rootkit / integrity / firewall -----------------------------------
    def rootkit_scan(self) -> list[Finding]:
        findings = rootkit.run_checks()
        for f in findings:
            if f.severity.rank >= Severity.MEDIUM.rank:
                self.db.add_event(f)
        return findings

    def fim_init(self) -> int:
        return integrity.build_baseline(self.db, self.config.fim_paths)

    def fim_check(self) -> list[Finding]:
        findings = integrity.check_integrity(self.db, self.config.fim_paths)
        for f in findings:
            if f.severity.rank >= Severity.MEDIUM.rank:
                self.db.add_event(f)
        return findings

    def firewall_status(self) -> firewall.FirewallStatus:
        return firewall.status()

    # -- real-time monitor -------------------------------------------------
    def build_monitor(self, on_event: object | None = None) -> RealtimeMonitor:
        self._monitor = RealtimeMonitor(
            self.scanner,
            self.quarantine,
            self.config.realtime_paths,
            auto_quarantine=self.config.realtime_auto_quarantine,
            on_event=on_event,  # type: ignore[arg-type]
            alert_webhook=self.config.alert_webhook,
        )
        return self._monitor

    @property
    def monitor(self) -> RealtimeMonitor | None:
        return self._monitor

    # -- signatures --------------------------------------------------------
    def add_hash_signature(self, sha256: str, name: str, severity: str) -> None:
        self.signatures.add_hash(sha256, name, severity_from_str(severity))

    def import_hashes(self, path: str, *, default_name: str = "Imported.Malware") -> dict[str, int]:
        """Bulk-import SHA-256 hashes from a file.

        Accepts plain one-hash-per-line lists and MalwareBazaar-style CSV exports
        (any 64-hex token on a line is taken as the hash; an adjacent signature
        label, if present, becomes the detection name). Lines without a 64-hex
        token are skipped.

        Returns a summary dict: ``{"added": n, "total_seen": m, "skipped": k}``.
        """
        import re
        from pathlib import Path as _Path

        from .models import Severity

        hex64 = re.compile(r"\b[0-9a-fA-F]{64}\b")
        items: list[tuple[str, str, Severity]] = []
        seen = skipped = 0
        text = _Path(path).read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "//")):
                continue
            m = hex64.search(line)
            if not m:
                skipped += 1
                continue
            seen += 1
            digest = m.group(0)
            # Try to lift a human label from CSV-ish remainder (e.g. signature col).
            rest = line.replace(digest, " ")
            label = ""
            for tok in re.split(r"[,;\t\"']+", rest):
                tok = tok.strip()
                if tok and not hex64.fullmatch(tok) and not tok.replace(".", "").isdigit():
                    label = tok
                    break
            name = label[:80] if label else default_name
            items.append((digest, name, Severity.HIGH))
        added = self.signatures.add_hashes_bulk(items)
        return {"added": added, "total_seen": seen, "skipped": skipped}

    def reload_signatures(self) -> None:
        self.signatures.reload()

    def update_rules(self, source: str, *, log: object | None = None) -> object:
        """Download a community YARA rule pack, then reload signatures."""
        from .updater import update as _update

        result = _update(self.paths, source, log=log)  # type: ignore[arg-type]
        self.reload_signatures()
        return result

    # -- status / reporting ------------------------------------------------
    def status(self) -> dict[str, object]:
        from .. import __version__

        last = self.db.last_scan()
        return {
            "version": __version__,
            "version_paths": {
                "config": str(self.paths.config_file),
                "data": str(self.paths.data_dir),
                "quarantine": str(self.paths.quarantine_dir),
            },
            "engines": self.scanner.engine_status(),
            "firewall": self.firewall_status().to_dict(),
            "realtime": {
                "running": self._monitor.running if self._monitor else False,
                "paths": self.config.realtime_paths,
                "auto_quarantine": self.config.realtime_auto_quarantine,
            },
            "counts": self.db.counts(),
            "last_scan": last,
            "config": self.config.to_dict(),
        }

    def save_config(self) -> None:
        save_config(self.paths, self.config)

    def close(self) -> None:
        if self._monitor is not None:
            self._monitor.stop()
        self.db.close()
