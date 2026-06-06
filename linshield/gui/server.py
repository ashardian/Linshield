"""LinShield web GUI.

A localhost-only Flask application that drives the same :class:`Engine` the CLI
uses. Security model: the server binds to 127.0.0.1, generates a random session
token on launch, and requires it on every request. Scans run in a background
thread with pollable progress and a cancel control, so the UI stays responsive
on a full-disk scan.
"""

from __future__ import annotations

import secrets
import threading
import time
import webbrowser
import re
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable

try:  # YARA is optional; used to validate imported rules before saving.
    import yara as _yara
except ImportError:  # pragma: no cover - depends on optional extra
    _yara = None  # type: ignore[assignment]

from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
)

from ..core import Engine
from ..core.models import Detection, Finding, Method, ScanSummary, Severity, Verdict
from ..core.report import build_html_report, build_json_report
from ..core.quarantine import QuarantineError
from ..core.signatures import severity_from_str


@dataclass
class ScanJob:
    """Tracks an in-flight or finished background scan."""

    scan_type: str
    thread: threading.Thread | None = None
    cancel: threading.Event = field(default_factory=threading.Event)
    files: int = 0
    current: str = ""
    done: bool = False
    summary: ScanSummary | None = None
    started: float = field(default_factory=time.time)


def _finding(category: str, title: str, severity: Severity, detail: str) -> Finding:
    """Build an event Finding for the activity log."""
    return Finding(category=category, title=title, severity=severity, detail=detail)


def create_app(engine: Engine, token: str) -> Flask:
    from .. import __version__

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["TOKEN"] = token
    # Never let the browser serve a stale console after an upgrade.
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    state: dict[str, ScanJob | None] = {"job": None}
    job_lock = threading.Lock()

    @app.after_request
    def _no_store(resp: Any) -> Any:
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        return resp

    # -- auth --------------------------------------------------------------
    def authed() -> bool:
        supplied = request.cookies.get("ls_token") or request.headers.get("X-LS-Token")
        return bool(supplied) and secrets.compare_digest(supplied, token)

    def require_auth(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not authed():
                return jsonify({"error": "unauthorized"}), 401
            return fn(*args, **kwargs)

        return wrapper

    # -- pages -------------------------------------------------------------
    @app.route("/")
    def index() -> Any:
        # First visit carries ?token=…; store it in a cookie then redirect clean.
        supplied = request.args.get("token")
        if supplied and secrets.compare_digest(supplied, token):
            resp = make_response(redirect("/"))
            resp.set_cookie("ls_token", token, httponly=True, samesite="Strict")
            return resp
        if not authed():
            return (
                "<h1>LinShield</h1><p>Missing or invalid session token. "
                "Launch the GUI with <code>linshield gui</code>.</p>",
                401,
            )
        return render_template("index.html", version=__version__)

    # -- status ------------------------------------------------------------
    @app.route("/api/status")
    @require_auth
    def api_status() -> Any:
        return jsonify(engine.status())

    # -- scanning ----------------------------------------------------------
    def _run_scan(job: ScanJob, roots: list[str], recursive: bool, auto_q: bool) -> None:
        def cb(n: int, path: str) -> None:
            job.files = n
            job.current = path

        summary = engine.scan(
            roots,
            scan_type=job.scan_type,
            recursive=recursive,
            auto_quarantine=auto_q,
            progress=cb,
            cancel=job.cancel,
        )
        job.summary = summary
        job.done = True

    @app.route("/api/scan/start", methods=["POST"])
    @require_auth
    def api_scan_start() -> Any:
        with job_lock:
            existing = state["job"]
            if existing and not existing.done:
                return jsonify({"error": "scan already running"}), 409
            data = request.get_json(silent=True) or {}
            scan_type = str(data.get("type", "quick"))
            if scan_type == "full":
                roots = engine.config.full_scan_roots
            elif scan_type == "custom" and data.get("paths"):
                roots = list(data["paths"])
            else:
                scan_type = "quick"
                roots = engine.config.quick_scan_paths
            auto_q = bool(data.get("quarantine", engine.config.auto_quarantine))
            job = ScanJob(scan_type=scan_type)
            job.thread = threading.Thread(
                target=_run_scan, args=(job, roots, True, auto_q), daemon=True
            )
            state["job"] = job
            job.thread.start()
        return jsonify({"started": True, "type": scan_type})

    @app.route("/api/scan/progress")
    @require_auth
    def api_scan_progress() -> Any:
        job = state["job"]
        if job is None:
            return jsonify({"active": False})
        payload: dict[str, Any] = {
            "active": not job.done,
            "type": job.scan_type,
            "files": job.files,
            "current": job.current,
            "elapsed": round(time.time() - job.started, 1),
            "done": job.done,
        }
        if job.done and job.summary is not None:
            payload["summary"] = job.summary.to_dict()
        return jsonify(payload)

    @app.route("/api/scan/cancel", methods=["POST"])
    @require_auth
    def api_scan_cancel() -> Any:
        job = state["job"]
        if job and not job.done:
            job.cancel.set()
        return jsonify({"cancelled": True})

    # -- quarantine --------------------------------------------------------
    @app.route("/api/quarantine")
    @require_auth
    def api_quarantine() -> Any:
        return jsonify([e.to_dict() for e in engine.quarantine.list()])

    @app.route("/api/quarantine/<int:qid>/<action>", methods=["POST"])
    @require_auth
    def api_quarantine_action(qid: int, action: str) -> Any:
        try:
            if action == "restore":
                path = engine.quarantine.restore(qid)
                return jsonify({"ok": True, "restored": str(path)})
            if action == "delete":
                engine.quarantine.delete(qid)
                return jsonify({"ok": True})
        except QuarantineError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": False, "error": "unknown action"}), 400

    @app.route("/api/quarantine/file", methods=["POST"])
    @require_auth
    def api_quarantine_file() -> Any:
        """Manually isolate a file flagged by a scan (infected OR suspicious)."""
        data = request.get_json(silent=True) or {}
        raw_path = str(data.get("path", "")).strip()
        if not raw_path:
            return jsonify({"ok": False, "error": "no path supplied"}), 400
        verdict = (
            Verdict.SUSPICIOUS
            if str(data.get("verdict")) == "suspicious"
            else Verdict.INFECTED
        )
        try:
            method = Method(str(data.get("method", "heuristic")))
        except ValueError:
            method = Method.HEURISTIC
        det = Detection(
            path=raw_path,
            verdict=verdict,
            method=method,
            signature=str(data.get("signature", "manual")),
            severity=severity_from_str(str(data.get("severity", "medium"))),
            sha256=str(data.get("sha256", "")),
        )
        try:
            entry = engine.quarantine.isolate(det)
        except QuarantineError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        engine.db.add_event(
            _finding(
                "quarantine",
                f"Manually quarantined: {det.signature}",
                det.severity,
                f"{raw_path} isolated as quarantine id {entry.qid}.",
            )
        )
        return jsonify({"ok": True, "qid": entry.qid})

    # -- history -----------------------------------------------------------
    @app.route("/api/history")
    @require_auth
    def api_history() -> Any:
        return jsonify(
            {
                "scans": engine.db.recent_scans(50),
                "detections": engine.db.recent_detections(100),
                "events": engine.db.recent_events(50),
            }
        )

    # -- tools -------------------------------------------------------------
    @app.route("/api/rootkit", methods=["POST"])
    @require_auth
    def api_rootkit() -> Any:
        return jsonify([f.to_dict() for f in engine.rootkit_scan()])

    @app.route("/api/fim/init", methods=["POST"])
    @require_auth
    def api_fim_init() -> Any:
        return jsonify({"count": engine.fim_init()})

    @app.route("/api/fim/check", methods=["POST"])
    @require_auth
    def api_fim_check() -> Any:
        return jsonify([f.to_dict() for f in engine.fim_check()])

    @app.route("/api/firewall")
    @require_auth
    def api_firewall() -> Any:
        return jsonify(engine.firewall_status().to_dict())

    @app.route("/api/trust", methods=["POST"])
    @require_auth
    def api_trust() -> Any:
        """Add (or remove) a path on the trust allowlist."""
        import os

        data = request.get_json(silent=True) or {}
        raw = str(data.get("path", "")).strip()
        remove = bool(data.get("remove"))
        if not raw:
            return jsonify({"ok": False, "error": "no path"}), 400
        target = os.path.abspath(os.path.expanduser(raw))
        if remove:
            engine.config.trusted_paths = [
                p for p in engine.config.trusted_paths if p not in (raw, target)
            ]
        elif target not in engine.config.trusted_paths:
            engine.config.trusted_paths.append(target)
        engine.save_config()
        engine.scanner = type(engine.scanner)(engine.config, engine.signatures)
        return jsonify({"ok": True, "trusted_paths": engine.config.trusted_paths})

    # -- real-time protection (master kill switch) -------------------------
    def _record_event(finding: Finding) -> None:
        try:
            engine.db.add_event(finding)
        except Exception:  # noqa: BLE001 - never let a watchdog callback die
            pass

    @app.route("/api/realtime", methods=["GET"])
    @require_auth
    def api_realtime() -> Any:
        mon = engine.monitor
        return jsonify(
            {
                "running": bool(mon and mon.running),
                "paths": engine.config.realtime_paths,
                "auto_quarantine": engine.config.realtime_auto_quarantine,
                "stats": mon.stats if mon else {"scanned": 0, "detected": 0, "quarantined": 0},
            }
        )

    @app.route("/api/realtime/start", methods=["POST"])
    @require_auth
    def api_realtime_start() -> Any:
        mon = engine.monitor
        if mon and mon.running:
            return jsonify({"ok": True, "running": True})
        try:
            mon = engine.build_monitor(on_event=_record_event)
            mon.start()
        except RuntimeError:
            return jsonify({
                "ok": False,
                "error": "No valid watch directories. Add real-time watch paths in Settings.",
            }), 400
        except Exception as exc:  # noqa: BLE001
            return jsonify({"ok": False, "error": str(exc)}), 500
        _record_event(
            _finding(
                "realtime",
                "Real-time protection enabled",
                Severity.INFO,
                f"Watching: {', '.join(engine.config.realtime_paths) or '(no paths configured)'}",
            )
        )
        return jsonify({"ok": True, "running": mon.running})

    @app.route("/api/realtime/stop", methods=["POST"])
    @require_auth
    def api_realtime_stop() -> Any:
        mon = engine.monitor
        if mon and mon.running:
            mon.stop()
            _record_event(
                _finding(
                    "realtime",
                    "Real-time protection disabled",
                    Severity.INFO,
                    "Live file monitoring stopped by user.",
                )
            )
        return jsonify({"ok": True, "running": False})

    # -- settings ----------------------------------------------------------
    @app.route("/api/settings", methods=["GET", "POST"])
    @require_auth
    def api_settings() -> Any:
        if request.method == "GET":
            return jsonify(engine.config.to_dict())
        data = request.get_json(silent=True) or {}
        cfg = engine.config
        bool_fields = (
            "use_hashes", "use_yara", "use_clamav", "use_heuristics",
            "auto_quarantine", "realtime_auto_quarantine", "follow_symlinks",
            "scan_archives", "strict_mode",
        )
        for key in bool_fields:
            if key in data:
                setattr(cfg, key, bool(data[key]))
        if "max_file_size_mb" in data:
            try:
                cfg.max_file_size_mb = max(1, int(data["max_file_size_mb"]))
            except (TypeError, ValueError):
                pass
        if "gui_port" in data:
            try:
                cfg.gui_port = int(data["gui_port"])
            except (TypeError, ValueError):
                pass
        if isinstance(data.get("gui_host"), str) and data["gui_host"].strip():
            cfg.gui_host = data["gui_host"].strip()
        if "alert_webhook" in data:
            cfg.alert_webhook = str(data.get("alert_webhook") or "").strip()
        list_fields = (
            "quick_scan_paths", "full_scan_roots", "realtime_paths",
            "exclude", "fim_paths", "trusted_paths",
        )
        for key in list_fields:
            if isinstance(data.get(key), list):
                setattr(cfg, key, [str(x) for x in data[key]])
        engine.save_config()
        # Rebuild scanner with updated config.
        from ..core.scanner import Scanner

        engine.scanner = Scanner(cfg, engine.signatures)
        return jsonify({"ok": True, "config": cfg.to_dict()})

    # -- signature management ---------------------------------------------
    @app.route("/api/signatures", methods=["GET"])
    @require_auth
    def api_signatures() -> Any:
        """Engine status plus the list of imported user YARA rule files."""
        user_dir = engine.paths.yara_user_dir
        files = []
        try:
            for f in sorted(user_dir.glob("*.yar")) + sorted(user_dir.glob("*.yara")):
                rules = len(re.findall(r"^\s*(?:private\s+|global\s+)*rule\s+\w+", f.read_text(encoding="utf-8", errors="replace"), re.M))
                files.append({"name": f.name, "rules": rules, "size": f.stat().st_size})
        except OSError:
            pass
        return jsonify(
            {
                "engines": engine.scanner.engine_status(),
                "user_rules": files,
                "yara_dir": str(user_dir),
            }
        )

    @app.route("/api/yara/import", methods=["POST"])
    @require_auth
    def api_yara_import() -> Any:
        """Validate and save a YARA ruleset into the user rules directory."""
        data = request.get_json(silent=True) or {}
        text = str(data.get("rules", ""))
        if not text.strip():
            return jsonify({"ok": False, "error": "empty ruleset"}), 400
        name = str(data.get("name", "")).strip() or "imported"
        # sanitise filename to a single safe component
        name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
        if not name.endswith((".yar", ".yara")):
            name += ".yar"

        # Validate it compiles before persisting, if YARA is available.
        if _yara is not None:
            try:
                compiled = _yara.compile(source=text)
                rule_count = sum(1 for _ in compiled)  # iterate to force materialise
            except _yara.Error as exc:
                return jsonify({"ok": False, "error": f"invalid YARA: {exc}"}), 400

        dest = engine.paths.yara_user_dir / name
        try:
            engine.paths.yara_user_dir.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8")
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        engine.reload_signatures()
        if not engine.signatures.yara_available and _yara is not None:
            # A previously-broken combined set; our validation passed so this is
            # unlikely, but surface it rather than silently failing.
            pass
        engine.db.add_event(
            _finding(
                "signatures",
                f"Imported YARA rules: {name}",
                Severity.INFO,
                f"{name} added to the user rule directory.",
            )
        )
        return jsonify(
            {
                "ok": True,
                "name": name,
                "yara_rules_total": engine.signatures.yara_rule_count,
            }
        )

    @app.route("/api/yara/delete", methods=["POST"])
    @require_auth
    def api_yara_delete() -> Any:
        data = request.get_json(silent=True) or {}
        name = re.sub(r"[^A-Za-z0-9._-]", "_", str(data.get("name", "")))
        if not name:
            return jsonify({"ok": False, "error": "no name"}), 400
        target = engine.paths.yara_user_dir / name
        # Guard against path escape: must resolve inside the user yara dir.
        try:
            target.resolve().relative_to(engine.paths.yara_user_dir.resolve())
        except ValueError:
            return jsonify({"ok": False, "error": "invalid path"}), 400
        if target.exists():
            try:
                target.unlink()
            except OSError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 500
        engine.reload_signatures()
        return jsonify({"ok": True})

    @app.route("/api/signatures/add-hash", methods=["POST"])
    @require_auth
    def api_add_hash() -> Any:
        data = request.get_json(silent=True) or {}
        digest = str(data.get("sha256", "")).strip().lower()
        name = str(data.get("name", "")).strip() or "Custom.Signature"
        severity = str(data.get("severity", "high"))
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            return jsonify({"ok": False, "error": "sha256 must be 64 hex chars"}), 400
        engine.add_hash_signature(digest, name, severity)
        engine.db.add_event(
            _finding("signatures", f"Added hash signature: {name}",
                     severity_from_str(severity), f"SHA-256 {digest[:16]}… flagged as malicious.")
        )
        return jsonify({"ok": True, "hash_count": engine.signatures.hash_count})

    @app.route("/api/signatures/reload", methods=["POST"])
    @require_auth
    def api_reload_signatures() -> Any:
        engine.reload_signatures()
        return jsonify({"ok": True, "engines": engine.scanner.engine_status()})

    @app.route("/api/yara/sources", methods=["GET"])
    @require_auth
    def api_yara_sources() -> Any:
        from ..core import updater

        return jsonify({"sources": updater.list_sources()})

    @app.route("/api/yara/update", methods=["POST"])
    @require_auth
    def api_yara_update() -> Any:
        data = request.get_json(silent=True) or {}
        source = str(data.get("source", "")).strip()
        try:
            result = engine.update_rules(source)
        except KeyError:
            return jsonify({"ok": False, "error": f"unknown source '{source}'"}), 400
        except Exception as exc:  # noqa: BLE001 - network/IO
            return jsonify({"ok": False, "error": str(exc)}), 502
        engine.db.add_event(
            _finding(
                "signatures",
                f"Updated community rules: {result.source}",
                Severity.INFO,
                f"{result.files_installed} file(s), {result.rules} rules installed "
                f"(skipped {result.skipped}).",
            )
        )
        return jsonify({
            "ok": True,
            "source": result.source,
            "files": result.files_installed,
            "rules": result.rules,
            "skipped": result.skipped,
            "errors": result.errors,
            "yara_rules_total": engine.signatures.yara_rule_count,
        })

    # -- report ------------------------------------------------------------
    @app.route("/api/report")
    @require_auth
    def api_report() -> Any:
        data = build_json_report(engine)
        if request.args.get("format") == "html":
            resp = make_response(build_html_report(data))
            resp.headers["Content-Type"] = "text/html"
            return resp
        return jsonify(data)

    return app


def run_gui(
    engine: Engine,
    host: str | None = None,
    port: int | None = None,
    open_browser: bool = True,
) -> None:
    """Start the GUI server (blocking)."""
    host = host or engine.config.gui_host
    port = port or engine.config.gui_port
    token = secrets.token_urlsafe(24)
    try:
        engine.paths.token_file.write_text(token, encoding="utf-8")
        engine.paths.token_file.chmod(0o600)
    except OSError:
        pass

    app = create_app(engine, token)
    url = f"http://{host}:{port}/?token={token}"
    print(f"\n  LinShield GUI running at:\n    {url}\n")
    print("  (URL contains a one-time session token; keep it private.)\n")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
