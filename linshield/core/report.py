"""Forensic report generation.

Builds a structured snapshot of LinShield's current state and recent activity
that can be emitted as JSON (for tooling/SIEM ingestion) or as a self-contained
HTML page (for humans). Used by both the CLI ``report`` command and the GUI.
"""

from __future__ import annotations

import html
import socket
import time
from typing import TYPE_CHECKING

from .. import __app_name__, __version__

if TYPE_CHECKING:  # avoid circular import at runtime
    from .engine import Engine


def build_json_report(engine: "Engine") -> dict[str, object]:
    """Assemble the full report payload as plain dictionaries."""
    return {
        "tool": __app_name__,
        "version": __version__,
        "generated": time.time(),
        "generated_human": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "host": socket.gethostname(),
        "status": engine.status(),
        "recent_scans": engine.db.recent_scans(25),
        "recent_detections": engine.db.recent_detections(100),
        "quarantine": [e.to_dict() for e in engine.quarantine.list(include_restored=True)],
        "events": engine.db.recent_events(100),
    }


def _sev_class(sev: str) -> str:
    return f"sev-{sev.lower()}"


def build_html_report(data: dict[str, object]) -> str:
    """Render the JSON report into a single, dependency-free HTML page."""
    status = data.get("status", {})  # type: ignore[assignment]
    engines = status.get("engines", {}) if isinstance(status, dict) else {}  # type: ignore[union-attr]
    counts = status.get("counts", {}) if isinstance(status, dict) else {}  # type: ignore[union-attr]

    def esc(value: object) -> str:
        return html.escape(str(value))

    det_rows = "".join(
        f"<tr class='{_sev_class(str(d.get('severity','')))}'>"
        f"<td>{esc(d.get('verdict'))}</td><td>{esc(d.get('severity'))}</td>"
        f"<td>{esc(d.get('signature'))}</td><td>{esc(d.get('method'))}</td>"
        f"<td class='path'>{esc(d.get('path'))}</td>"
        f"<td>{esc(time.strftime('%Y-%m-%d %H:%M', time.localtime(float(d.get('ts', 0)))))}</td></tr>"
        for d in data.get("recent_detections", [])  # type: ignore[union-attr]
    ) or "<tr><td colspan='6'>No detections recorded.</td></tr>"

    scan_rows = "".join(
        f"<tr><td>{esc(s.get('id'))}</td><td>{esc(s.get('scan_type'))}</td>"
        f"<td>{esc(time.strftime('%Y-%m-%d %H:%M', time.localtime(float(s.get('ended', 0)))))}</td>"
        f"<td>{esc(s.get('files'))}</td><td>{esc(s.get('infected'))}</td>"
        f"<td>{esc(s.get('suspicious'))}</td><td>{esc(s.get('quarantined'))}</td></tr>"
        for s in data.get("recent_scans", [])  # type: ignore[union-attr]
    ) or "<tr><td colspan='7'>No scans recorded.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{esc(data.get('tool'))} report — {esc(data.get('host'))}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: ui-monospace, "JetBrains Mono", Menlo, monospace;
          background:#0c0f14; color:#d6deeb; margin:0; padding:2rem; }}
  h1 {{ font-size:1.4rem; letter-spacing:.04em; }}
  .meta {{ color:#7c8aa5; margin-bottom:2rem; }}
  .cards {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:2rem; }}
  .card {{ background:#141925; border:1px solid #232c3d; border-radius:10px;
           padding:1rem 1.25rem; min-width:130px; }}
  .card .n {{ font-size:1.8rem; font-weight:700; }}
  .card .l {{ color:#7c8aa5; font-size:.8rem; }}
  table {{ width:100%; border-collapse:collapse; margin-bottom:2rem; font-size:.85rem; }}
  th,td {{ text-align:left; padding:.5rem .6rem; border-bottom:1px solid #1d2433; }}
  th {{ color:#9bb3d4; text-transform:uppercase; font-size:.72rem; letter-spacing:.05em; }}
  td.path {{ word-break:break-all; color:#a8b6cf; }}
  .sev-critical td {{ background:rgba(220,38,38,.18); }}
  .sev-high td {{ background:rgba(234,88,12,.14); }}
  .sev-medium td {{ background:rgba(202,138,4,.10); }}
</style></head><body>
<h1>🛡 {esc(data.get('tool'))} {esc(data.get('version'))} — forensic report</h1>
<div class="meta">Host {esc(data.get('host'))} · Generated {esc(data.get('generated_human'))}</div>
<div class="cards">
  <div class="card"><div class="n">{esc(counts.get('scans', 0))}</div><div class="l">Scans</div></div>
  <div class="card"><div class="n">{esc(counts.get('detections', 0))}</div><div class="l">Detections</div></div>
  <div class="card"><div class="n">{esc(counts.get('quarantine', 0))}</div><div class="l">Quarantined</div></div>
  <div class="card"><div class="n">{esc(counts.get('baseline', 0))}</div><div class="l">FIM baseline</div></div>
  <div class="card"><div class="n">{esc(engines.get('yara', {}).get('rules', 0) if isinstance(engines, dict) else 0)}</div><div class="l">YARA rules</div></div>
</div>
<h2>Recent detections</h2>
<table><thead><tr><th>Verdict</th><th>Severity</th><th>Signature</th><th>Method</th><th>Path</th><th>When</th></tr></thead>
<tbody>{det_rows}</tbody></table>
<h2>Scan history</h2>
<table><thead><tr><th>ID</th><th>Type</th><th>When</th><th>Files</th><th>Infected</th><th>Suspicious</th><th>Quarantined</th></tr></thead>
<tbody>{scan_rows}</tbody></table>
</body></html>"""
