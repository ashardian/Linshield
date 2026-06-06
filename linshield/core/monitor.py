"""Real-time protection.

Watches the configured directories with the OS file-change API (inotify via
``watchdog``). When a file is created or modified it is scanned immediately;
infected files are optionally auto-quarantined. Designed to run either in the
foreground (``linshield monitor``) or as a systemd service.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .models import Detection, Finding, Method, Severity, Verdict
from .quarantine import Quarantine, QuarantineError
from .scanner import Scanner

logger = logging.getLogger("linshield.monitor")


def _notify(title: str, body: str) -> None:
    """Best-effort desktop notification via notify-send (no-op if unavailable)."""
    notify = shutil.which("notify-send")
    if not notify:
        return
    try:
        subprocess.run(  # noqa: S603 - fixed argv
            [notify, "-a", "LinShield", "-u", "critical", title, body],
            timeout=5,
            check=False,
            capture_output=True,
        )
    except (OSError, subprocess.SubprocessError):
        pass

EventCallback = Callable[[Finding], None]


class _Handler(FileSystemEventHandler):
    """Debounces and scans files as filesystem events arrive."""

    def __init__(self, monitor: "RealtimeMonitor") -> None:
        self._monitor = monitor
        self._recent: dict[str, float] = {}

    def _should_scan(self, path: str) -> bool:
        now = time.time()
        last = self._recent.get(path, 0.0)
        # Debounce rapid repeated writes to the same file (e.g. downloads).
        if now - last < 1.5:
            return False
        self._recent[path] = now
        # Opportunistic cleanup of the debounce map.
        if len(self._recent) > 4096:
            cutoff = now - 30
            self._recent = {k: v for k, v in self._recent.items() if v > cutoff}
        return True

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._dispatch(str(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._dispatch(str(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        dest = getattr(event, "dest_path", None)
        if dest and not event.is_directory:
            self._dispatch(str(dest))

    def _dispatch(self, path: str) -> None:
        if not self._should_scan(path):
            return
        self._monitor.handle_file(Path(path))


class RealtimeMonitor:
    """Coordinates watchdog observers and reacts to detections."""

    def __init__(
        self,
        scanner: Scanner,
        quarantine: Quarantine,
        paths: list[str],
        *,
        auto_quarantine: bool = True,
        on_event: EventCallback | None = None,
        alert_webhook: str = "",
    ) -> None:
        self.scanner = scanner
        self.quarantine = quarantine
        self.paths = paths
        self.auto_quarantine = auto_quarantine
        self.on_event = on_event
        self.alert_webhook = alert_webhook
        self._observer: Observer | None = None  # type: ignore[valid-type]
        self._lock = threading.Lock()
        self.stats = {"scanned": 0, "detected": 0, "quarantined": 0}

    def handle_file(self, path: Path) -> None:
        """Scan a single changed file and act on any detection."""
        try:
            detections = self.scanner.scan_file(path)
        except Exception as exc:  # noqa: BLE001 - never let a handler die
            logger.warning("Scan error for %s: %s", path, exc)
            return
        with self._lock:
            self.stats["scanned"] += 1
        if not detections:
            return
        with self._lock:
            self.stats["detected"] += 1  # count the file once, not per-engine-hit

        from . import confidence

        confidence.annotate_one(detections)
        for det in detections:
            self._emit_detection(det)
        self._post_webhook(detections)

        # Only ever auto-quarantine definitive (CONFIRMED) detections, exactly
        # like on-demand scans. A pattern hit on a freshly-written file is far
        # too weak to silently isolate the user's files on.
        if self.auto_quarantine and confidence.quarantine_worthy(detections):
            definitive = next(
                (d for d in detections if d.method in (Method.HASH, Method.CLAMAV)),
                detections[0],
            )
            self._auto_quarantine(definitive)

    def _emit_detection(self, det: Detection) -> None:
        sev = det.severity if det.verdict is Verdict.INFECTED else Severity.LOW
        finding = Finding(
            category="realtime",
            title=f"{det.verdict.value.upper()}: {det.signature}",
            severity=sev,
            detail=f"{det.path} (via {det.method.value})",
        )
        logger.warning("%s — %s", finding.title, finding.detail)
        if self.on_event is not None:
            self.on_event(finding)

    def _post_webhook(self, detections: list[Detection]) -> None:
        """Best-effort JSON POST to the configured alert endpoint (non-blocking)."""
        if not self.alert_webhook:
            return
        top = max(detections, key=lambda d: d.severity.rank)
        payload = {
            "source": "linshield-realtime",
            "path": top.path,
            "signature": top.signature,
            "method": top.method.value,
            "severity": top.severity.value,
            "confidence": top.confidence.value if top.confidence else None,
            "count": len({d.path for d in detections}),
            "timestamp": time.time(),
        }

        def _send() -> None:
            import json as _json
            import urllib.request

            try:
                req = urllib.request.Request(
                    self.alert_webhook,
                    data=_json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json",
                             "User-Agent": "LinShield-Alert/1.0"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=10)  # noqa: S310 - user-configured URL
            except Exception as exc:  # noqa: BLE001 - alerting must never crash the monitor
                logger.warning("Webhook alert failed: %s", exc)

        threading.Thread(target=_send, daemon=True).start()

    def _auto_quarantine(self, det: Detection) -> None:
        try:
            entry = self.quarantine.isolate(det)
        except QuarantineError as exc:
            logger.error("Auto-quarantine failed for %s: %s", det.path, exc)
            return
        with self._lock:
            self.stats["quarantined"] += 1
        logger.warning("Quarantined %s -> id %d", det.path, entry.qid)
        _notify(
            "LinShield: threat quarantined",
            f"{Path(det.path).name} ({det.signature})",
        )
        if self.on_event is not None:
            self.on_event(
                Finding(
                    category="realtime",
                    title=f"Quarantined: {det.signature}",
                    severity=det.severity,
                    detail=f"{det.path} isolated as quarantine id {entry.qid}.",
                )
            )

    def start(self) -> None:
        observer = Observer()
        handler = _Handler(self)
        watched = 0
        for raw in self.paths:
            p = Path(raw)
            if p.is_dir():
                observer.schedule(handler, str(p), recursive=True)
                watched += 1
        if watched == 0:
            raise RuntimeError("No valid directories to watch.")
        observer.start()
        self._observer = observer
        logger.info("Real-time protection watching %d path(s).", watched)

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None

    @property
    def running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    def run_forever(self) -> None:
        """Blocking loop for foreground / systemd use."""
        self.start()
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
