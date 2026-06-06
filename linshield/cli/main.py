"""LinShield command-line interface.

A complete CLI built on ``click``. Every capability the GUI exposes is
available here too, so the tool is fully usable headless (servers, SSH,
cron/systemd). Output uses ``rich`` when available and degrades to plain text
otherwise.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

import click

from .. import __app_name__, __version__
from ..core import Engine, Severity, setup_logging
from ..core.config import Paths
from ..core.models import ScanSummary, Verdict

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table

    _console: "Console | None" = Console()
except ImportError:  # pragma: no cover
    _console = None


# --------------------------------------------------------------------------
# Output helpers (rich-aware, plain fallback)
# --------------------------------------------------------------------------
_SEV_COLOUR = {
    "info": "cyan",
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold white on red",
}


def echo(msg: str = "") -> None:
    if _console:
        _console.print(msg)
    else:
        click.echo(_strip_markup(msg))


def _strip_markup(msg: str) -> str:
    import re

    return re.sub(r"\[/?[^\]]*\]", "", msg)


def _sev_tag(sev: str) -> str:
    colour = _SEV_COLOUR.get(sev, "white")
    return f"[{colour}]{sev.upper()}[/{colour}]" if _console else sev.upper()


def _fmt_bytes(n: int) -> str:
    val = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if val < 1024 or unit == "TiB":
            return f"{val:.1f} {unit}"
        val /= 1024
    return f"{n} B"


# --------------------------------------------------------------------------
# Engine context
# --------------------------------------------------------------------------
class Ctx:
    def __init__(self, verbose: bool) -> None:
        self.paths = Paths.resolve()
        setup_logging(self.paths, verbose=verbose)
        self.engine = Engine(self.paths)


pass_ctx = click.make_pass_decorator(Ctx)


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    help=f"{__app_name__} — open-source endpoint security for Linux.",
)
@click.version_option(__version__, prog_name=__app_name__)
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    ctx.obj = Ctx(verbose)


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------
@cli.command()
@click.argument("paths", nargs=-1, type=click.Path())
@click.option("--quick", is_flag=True, help="Scan common malware hotspots.")
@click.option("--full", is_flag=True, help="Scan the entire filesystem.")
@click.option("--no-recursive", is_flag=True, help="Do not descend into directories.")
@click.option("--quarantine", "do_q", is_flag=True, help="Auto-quarantine infected files.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.option(
    "--min-severity",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    default=None,
    help="Hide findings below this severity from the output.",
)
@pass_ctx
def scan(
    ctx: Ctx,
    paths: tuple[str, ...],
    quick: bool,
    full: bool,
    no_recursive: bool,
    do_q: bool,
    as_json: bool,
    min_severity: str | None,
) -> None:
    """Scan PATHS (or use --quick / --full) for malware."""
    engine = ctx.engine
    if full:
        roots: list[str] = engine.config.full_scan_roots
        scan_type = "full"
    elif quick or not paths:
        roots = engine.config.quick_scan_paths
        scan_type = "quick"
    else:
        roots = list(paths)
        scan_type = "custom"

    cancel = threading.Event()
    summary: ScanSummary
    _t0 = time.monotonic()

    if _console and not as_json:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=_console,
            transient=True,
        ) as progress:
            task = progress.add_task("Scanning…", total=None)

            def cb(n: int, path: str) -> None:
                elapsed = time.monotonic() - _t0
                rate = n / elapsed if elapsed > 0 else 0
                progress.update(
                    task,
                    description=f"Scanned {n} files ({rate:.0f}/s) — {path[:50]}",
                )

            summary = engine.scan(
                roots,
                scan_type=scan_type,
                recursive=not no_recursive,
                auto_quarantine=do_q,
                progress=cb,
                cancel=cancel,
            )
    else:
        summary = engine.scan(
            roots,
            scan_type=scan_type,
            recursive=not no_recursive,
            auto_quarantine=do_q,
        )

    if as_json:
        click.echo(json.dumps(summary.to_dict(), indent=2))
    else:
        _print_scan_summary(summary, strict=engine.config.strict_mode, min_severity=min_severity)
    engine.close()
    # Exit 2 only for definitive (CONFIRMED) threats; 1 for LIKELY; 0 otherwise.
    # Lone pattern hits (REVIEW) are not failures — they're informational.
    sys.exit(2 if summary.confirmed else (1 if summary.likely else 0))


def _print_scan_summary(
    summary: ScanSummary, strict: bool = False, min_severity: str | None = None
) -> None:
    from ..core.models import Confidence, Severity

    echo()
    floor = Severity(min_severity).rank if min_severity else -1
    # Group detections by file and bucket files into confidence tiers.
    tiers: dict[Confidence, dict[str, list]] = {
        Confidence.CONFIRMED: {}, Confidence.LIKELY: {}, Confidence.REVIEW: {}
    }
    for d in summary.detections:
        if d.severity.rank < floor:
            continue
        tier = d.confidence or Confidence.REVIEW
        if tier in tiers:
            tiers[tier].setdefault(d.path, []).append(d)
    if min_severity:
        echo(f"[dim]Filtered to severity ≥ {min_severity}.[/dim]")

    def render(tier: Confidence, title: str, colour: str) -> None:
        files = tiers[tier]
        if not files:
            return
        if _console:
            table = Table(title=f"{title} ({len(files)})", show_lines=False, expand=True)
            table.add_column("Severity")
            table.add_column("Signature")
            table.add_column("Method")
            table.add_column("Path", overflow="fold")
            for path, dets in files.items():
                top = max(dets, key=lambda x: x.severity.rank)
                sigs = ", ".join(sorted({x.signature for x in dets}))
                methods = ", ".join(sorted({x.method.value for x in dets}))
                table.add_row(_sev_tag(top.severity.value), sigs, methods, path)
            _console.print(table)
        else:
            echo(f"{title} ({len(files)}):")
            for path, dets in files.items():
                sigs = ", ".join(sorted({x.signature for x in dets}))
                echo(f"  {path} — {sigs}")

    render(Confidence.CONFIRMED, "🔴 Confirmed threats", "red")
    render(Confidence.LIKELY, "🟠 Likely threats", "yellow")
    if not strict:
        render(Confidence.REVIEW, "🔵 For review (low confidence)", "cyan")
        if tiers[Confidence.REVIEW]:
            echo(
                "[dim]Review items are single pattern/heuristic matches. These are "
                "frequently false positives — common on security tools, installers "
                "and source code. Investigate before acting; nothing here was "
                "quarantined automatically.[/dim]"
            )

    # Headline summary, led by the confirmed count.
    if summary.is_clean:
        verdict_line = "[bold green]✓ No threats found[/bold green]"
    elif summary.confirmed:
        verdict_line = f"[bold red]⚠ {summary.confirmed} confirmed[/bold red], {summary.likely} likely, {summary.review} to review"
    elif summary.likely:
        verdict_line = f"[bold yellow]{summary.likely} likely threat(s)[/bold yellow], {summary.review} to review — no confirmed threats"
    else:
        hidden = " (hidden by strict mode)" if strict else ""
        verdict_line = f"[bold cyan]{summary.review} item(s) to review{hidden}[/bold cyan] — no confirmed or likely threats"

    body = (
        f"{verdict_line}\n"
        f"Files scanned : {summary.files_scanned}\n"
        f"Data scanned  : {_fmt_bytes(summary.bytes_scanned)}\n"
        f"Errors        : {summary.errors}\n"
        f"Quarantined   : {summary.auto_quarantined} (confirmed only)\n"
        f"Duration      : {summary.duration:.2f}s"
    )
    if _console:
        _console.print(Panel(body, title=f"Scan complete ({summary.scan_type})", expand=False))
    else:
        echo(body)


# --------------------------------------------------------------------------
# monitor
# --------------------------------------------------------------------------
@cli.command()
@pass_ctx
def monitor(ctx: Ctx) -> None:
    """Start real-time protection in the foreground (Ctrl-C to stop)."""
    engine = ctx.engine

    def on_event(finding: object) -> None:
        f = finding  # type: ignore[assignment]
        echo(f"{_sev_tag(f.severity.value)} {f.title} — {f.detail}")  # type: ignore[attr-defined]

    mon = engine.build_monitor(on_event=on_event)
    echo(f"[bold]Real-time protection[/bold] watching: {', '.join(engine.config.realtime_paths)}")
    echo("Press Ctrl-C to stop.\n")
    try:
        mon.run_forever()
    finally:
        echo(
            f"\nStopped. Scanned {mon.stats['scanned']}, "
            f"detected {mon.stats['detected']}, quarantined {mon.stats['quarantined']}."
        )
        engine.close()


# --------------------------------------------------------------------------
# quarantine
# --------------------------------------------------------------------------
@cli.group()
def quarantine() -> None:
    """Manage isolated files."""


@quarantine.command("list")
@pass_ctx
def q_list(ctx: Ctx) -> None:
    """List quarantined files."""
    entries = ctx.engine.quarantine.list()
    if not entries:
        echo("Quarantine is empty.")
    elif _console:
        table = Table(title="Quarantine")
        table.add_column("ID")
        table.add_column("Severity")
        table.add_column("Signature")
        table.add_column("Original path", overflow="fold")
        table.add_column("Size")
        for e in entries:
            table.add_row(str(e.qid), _sev_tag(e.severity), e.signature, e.original_path, _fmt_bytes(e.size))
        _console.print(table)
    else:
        for e in entries:
            echo(f"  #{e.qid} [{e.severity}] {e.signature} {e.original_path} ({_fmt_bytes(e.size)})")
    ctx.engine.close()


@quarantine.command("restore")
@click.argument("qid", type=int)
@pass_ctx
def q_restore(ctx: Ctx, qid: int) -> None:
    """Restore a quarantined file to its original location."""
    from ..core.quarantine import QuarantineError

    try:
        path = ctx.engine.quarantine.restore(qid)
        echo(f"[green]Restored[/green] -> {path}")
    except QuarantineError as exc:
        echo(f"[red]Error:[/red] {exc}")
    ctx.engine.close()


@quarantine.command("delete")
@click.argument("qid", type=int)
@click.confirmation_option(prompt="Permanently delete this quarantined file?")
@pass_ctx
def q_delete(ctx: Ctx, qid: int) -> None:
    """Permanently delete a quarantined file."""
    from ..core.quarantine import QuarantineError

    try:
        ctx.engine.quarantine.delete(qid)
        echo(f"[green]Deleted[/green] quarantine #{qid}")
    except QuarantineError as exc:
        echo(f"[red]Error:[/red] {exc}")
    ctx.engine.close()


# --------------------------------------------------------------------------
# rootkit / fim / firewall
# --------------------------------------------------------------------------
@cli.command()
@click.option("--json", "as_json", is_flag=True)
@pass_ctx
def rootkit(ctx: Ctx, as_json: bool) -> None:
    """Run rootkit / indicator-of-compromise checks."""
    findings = ctx.engine.rootkit_scan()
    _print_findings(findings, "Rootkit / IOC scan", as_json)
    ctx.engine.close()


@cli.group()
def fim() -> None:
    """File-integrity monitoring."""


@fim.command("init")
@pass_ctx
def fim_init(ctx: Ctx) -> None:
    """Capture a baseline of critical system files."""
    echo("Building integrity baseline… (this may take a moment)")
    count = ctx.engine.fim_init()
    echo(f"[green]Baseline captured:[/green] {count} files hashed.")
    ctx.engine.close()


@fim.command("check")
@click.option("--json", "as_json", is_flag=True)
@pass_ctx
def fim_check(ctx: Ctx, as_json: bool) -> None:
    """Check current state against the baseline."""
    findings = ctx.engine.fim_check()
    _print_findings(findings, "Integrity check", as_json)
    ctx.engine.close()


@cli.command()
@click.option("--json", "as_json", is_flag=True)
@pass_ctx
def firewall(ctx: Ctx, as_json: bool) -> None:
    """Show firewall status."""
    st = ctx.engine.firewall_status()
    if as_json:
        click.echo(json.dumps(st.to_dict(), indent=2))
    else:
        state = "[green]ACTIVE[/green]" if st.active else "[red]INACTIVE[/red]"
        echo(f"Backend: [bold]{st.backend}[/bold]  Status: {state}")
        echo(st.detail)
    ctx.engine.close()


def _print_findings(findings: list[object], title: str, as_json: bool) -> None:
    if as_json:
        click.echo(json.dumps([f.to_dict() for f in findings], indent=2))  # type: ignore[attr-defined]
        return
    if _console:
        table = Table(title=title)
        table.add_column("Severity")
        table.add_column("Finding")
        table.add_column("Detail", overflow="fold")
        for f in sorted(findings, key=lambda x: -x.severity.rank):  # type: ignore[attr-defined]
            table.add_row(_sev_tag(f.severity.value), f.title, f.detail)  # type: ignore[attr-defined]
        _console.print(table)
    else:
        for f in findings:
            echo(f"  [{f.severity.value}] {f.title}: {f.detail}")  # type: ignore[attr-defined]


# --------------------------------------------------------------------------
# status / history / signatures / report
# --------------------------------------------------------------------------
@cli.command()
@click.option("--json", "as_json", is_flag=True)
@pass_ctx
def status(ctx: Ctx, as_json: bool) -> None:
    """Show overall protection status."""
    st = ctx.engine.status()
    if as_json:
        click.echo(json.dumps(st, indent=2, default=str))
        ctx.engine.close()
        return
    eng = st["engines"]  # type: ignore[index]
    fw = st["firewall"]  # type: ignore[index]
    counts = st["counts"]  # type: ignore[index]
    lines = [
        f"[bold]{__app_name__} {__version__}[/bold]",
        "",
        "[bold]Detection engines[/bold]",
        f"  Hash DB    : {'on' if eng['hashes']['enabled'] else 'off'} ({eng['hashes']['count']} signatures)",
        f"  YARA       : {'available' if eng['yara']['available'] else 'unavailable'} ({eng['yara']['rules']} rules)",
        f"  ClamAV     : {eng['clamav']['engine']}",
        f"  Heuristics : {'on' if eng['heuristics']['enabled'] else 'off'}",
        "",
        f"[bold]Firewall[/bold]: {fw['backend']} — {'active' if fw['active'] else 'inactive'}",
        "",
        "[bold]History[/bold]",
        f"  Scans      : {counts['scans']}",
        f"  Detections : {counts['detections']}",
        f"  Quarantine : {counts['quarantine']}",
        f"  FIM baseline: {counts['baseline']} files",
    ]
    if st.get("last_scan"):
        ls = st["last_scan"]  # type: ignore[index]
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(ls["ended"]))  # type: ignore[index]
        lines += ["", f"[bold]Last scan[/bold]: {ls['scan_type']} at {when} — {ls['infected']} infected"]  # type: ignore[index]
    if _console:
        _console.print(Panel("\n".join(lines), expand=False))
    else:
        echo("\n".join(lines))
    ctx.engine.close()


@cli.command()
@click.option("--limit", default=15, help="Number of scans to show.")
@pass_ctx
def history(ctx: Ctx, limit: int) -> None:
    """Show recent scan history."""
    scans = ctx.engine.db.recent_scans(limit)
    if not scans:
        echo("No scans recorded yet.")
    elif _console:
        table = Table(title="Scan history")
        for col in ("ID", "Type", "When", "Files", "Infected", "Suspicious", "Quarantined"):
            table.add_column(col)
        for s in scans:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(s["ended"]))
            table.add_row(
                str(s["id"]), str(s["scan_type"]), when, str(s["files"]),
                str(s["infected"]), str(s["suspicious"]), str(s["quarantined"]),
            )
        _console.print(table)
    else:
        for s in scans:
            echo(f"  #{s['id']} {s['scan_type']} files={s['files']} infected={s['infected']}")
    ctx.engine.close()


@cli.group()
def signatures() -> None:
    """Manage detection signatures."""


@signatures.command("add-hash")
@click.argument("sha256")
@click.argument("name")
@click.option("--severity", default="high", type=click.Choice([s.value for s in Severity]))
@pass_ctx
def sig_add(ctx: Ctx, sha256: str, name: str, severity: str) -> None:
    """Add a known-malicious SHA-256 to the hash database."""
    ctx.engine.add_hash_signature(sha256, name, severity)
    echo(f"[green]Added[/green] {name} ({severity}) -> {sha256}")
    ctx.engine.close()


@signatures.command("reload")
@pass_ctx
def sig_reload(ctx: Ctx) -> None:
    """Reload hash and YARA signatures from disk."""
    ctx.engine.reload_signatures()
    st = ctx.engine.scanner.engine_status()
    echo(f"Reloaded: {st['hashes']['count']} hashes, {st['yara']['rules']} YARA rules.")  # type: ignore[index]
    ctx.engine.close()


@signatures.command("import-hashes")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--name", default="Imported.Malware", help="Default signature name.")
@pass_ctx
def sig_import_hashes(ctx: Ctx, file: str, name: str) -> None:
    """Bulk-import SHA-256 hashes (plain list or MalwareBazaar CSV export)."""
    echo(f"Importing hashes from [cyan]{file}[/cyan] …")
    try:
        result = ctx.engine.import_hashes(file, default_name=name)
    except OSError as exc:
        echo(f"[red]Could not read file:[/red] {exc}")
        ctx.engine.close()
        raise SystemExit(1)
    st = ctx.engine.scanner.engine_status()
    echo(
        f"[green]Done.[/green] Added {result['added']} new hash(es) "
        f"({result['total_seen']} seen, {result['skipped']} lines skipped). "
        f"Hash DB now holds {st['hashes']['count']} signatures."  # type: ignore[index]
    )
    echo(
        "[dim]Free hash feeds include MalwareBazaar (bazaar.abuse.ch) CSV "
        'exports. Stored as JSON: {"<sha256>": {"name": "...", "severity": '
        '"high"}}.[/dim]'
    )
    ctx.engine.close()


@cli.group()
def config() -> None:
    """Inspect and validate configuration."""


@config.command("validate")
@pass_ctx
def config_validate(ctx: Ctx) -> None:
    """Check that the on-disk config file parses and is well-formed."""
    import json as _json

    from ..core.config import Config

    path = ctx.engine.paths.config_file
    if not path.exists():
        echo(f"[yellow]No config file at {path}[/yellow] — defaults are in use (valid).")
        ctx.engine.close()
        return
    try:
        raw = _json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        echo(f"[red]✗ Invalid config[/red] at {path}: {exc}")
        echo("The next scan would silently fall back to defaults. Fix or delete the file.")
        ctx.engine.close()
        raise SystemExit(1)
    known = set(Config.__dataclass_fields__)  # type: ignore[attr-defined]
    unknown = sorted(set(raw) - known)
    echo(f"[green]✓ Config parses[/green] ({path})")
    if unknown:
        echo(f"[yellow]Note:[/yellow] ignored unknown keys: {', '.join(unknown)}")
    else:
        echo("All keys recognised.")
    ctx.engine.close()


@cli.command()
@click.argument("path", required=False)
@click.option("--list", "list_only", is_flag=True, help="List trusted paths.")
@click.option("--remove", "remove", metavar="PATH", help="Remove a trusted path.")
@pass_ctx
def trust(ctx: Ctx, path: str | None, list_only: bool, remove: str | None) -> None:
    """Manage trusted paths (an allowlist LinShield will never scan or flag)."""
    import os

    cfg = ctx.engine.config

    if remove:
        target = os.path.abspath(os.path.expanduser(remove))
        before = len(cfg.trusted_paths)
        cfg.trusted_paths = [p for p in cfg.trusted_paths if p not in (remove, target)]
        if len(cfg.trusted_paths) < before:
            ctx.engine.save_config()
            echo(f"[green]Untrusted:[/green] {remove}")
        else:
            echo(f"[yellow]Not in trusted list:[/yellow] {remove}")
        ctx.engine.close()
        return

    if list_only or not path:
        if cfg.trusted_paths:
            echo("[bold]Trusted paths (allowlisted):[/bold]")
            for p in cfg.trusted_paths:
                echo(f"  {p}")
        else:
            echo("No trusted paths configured. Add one: [bold]linshield trust <path>[/bold]")
        ctx.engine.close()
        return

    target = os.path.abspath(os.path.expanduser(path))
    if target not in cfg.trusted_paths:
        cfg.trusted_paths.append(target)
        ctx.engine.save_config()
        echo(f"[green]Trusted:[/green] {target}")
        echo("LinShield will no longer scan or flag files under this path.")
    else:
        echo(f"Already trusted: {target}")
    ctx.engine.close()


@cli.command()
@click.argument("source", required=False)
@click.option("--list", "list_only", is_flag=True, help="List available rule sources.")
@pass_ctx
def update(ctx: Ctx, source: str | None, list_only: bool) -> None:
    """Download community YARA rule packs (e.g. 'yara-forge-core', 'elastic-linux')."""
    from ..core import updater

    if list_only or not source:
        echo("[bold]Available community rule sources:[/bold]")
        for s in updater.list_sources():
            echo(f"  [cyan]{s['name']}[/cyan] — {s['description']}")
            echo(f"      license: {s['license']}")
        if not source:
            echo("\nRun: [bold]linshield update <source>[/bold]")
        ctx.engine.close()
        return

    echo(f"Updating rules from [cyan]{source}[/cyan] …")
    try:
        result = ctx.engine.update_rules(source, log=lambda m: echo(m))
    except KeyError:
        echo(f"[red]Unknown source:[/red] {source}. Use --list to see options.")
        ctx.engine.close()
        raise SystemExit(1)
    except Exception as exc:  # noqa: BLE001 - network/IO
        echo(f"[red]Update failed:[/red] {exc}")
        ctx.engine.close()
        raise SystemExit(1)

    st = ctx.engine.scanner.engine_status()
    echo(
        f"\n[green]Done.[/green] Installed {result.files_installed} file(s), "
        f"{result.rules} rules, skipped {result.skipped}. "
        f"Engine now has {st['yara']['rules']} YARA rules."  # type: ignore[index]
    )
    if result.errors:
        for e in result.errors:
            echo(f"[yellow]note:[/yellow] {e}")
    ctx.engine.close()


@cli.command()
@click.option("--output", "-o", type=click.Path(), help="Write report to a file.")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "html"]))
@pass_ctx
def report(ctx: Ctx, output: str | None, fmt: str) -> None:
    """Generate a forensic report of recent activity."""
    from ..core.report import build_html_report, build_json_report

    data = build_json_report(ctx.engine)
    content = json.dumps(data, indent=2, default=str) if fmt == "json" else build_html_report(data)
    if output:
        Path(output).write_text(content, encoding="utf-8")
        echo(f"[green]Report written:[/green] {output}")
    else:
        click.echo(content)
    ctx.engine.close()


# --------------------------------------------------------------------------
# gui
# --------------------------------------------------------------------------
@cli.command()
@click.option("--host", default=None, help="Bind host (default 127.0.0.1).")
@click.option("--port", default=None, type=int, help="Bind port (default 8920).")
@click.option("--no-browser", is_flag=True, help="Do not open a browser.")
@pass_ctx
def gui(ctx: Ctx, host: str | None, port: int | None, no_browser: bool) -> None:
    """Launch the web GUI (binds to localhost)."""
    from ..gui.server import run_gui

    run_gui(ctx.engine, host=host, port=port, open_browser=not no_browser)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
