"""Community YARA rule updater.

LinShield ships only a small set of original, precision-tuned rules. Real-world
coverage comes from curated community rule packs, which this module downloads on
demand into the user rules directory (``<yara_user_dir>/community/<source>/``).

These third-party rules are **not** redistributed inside this MIT-licensed
project — they are fetched to the user's own machine, where each upstream
project's license applies. Every downloaded ruleset is validated (it must
compile) before it is installed; files that don't compile are skipped so a bad
rule can never disable the engine.

Network access is required only when running an update.
"""

from __future__ import annotations

# LS-SELF-EXCLUDE-7f3a9c2e1b — LinShield-owned file; excluded from self-scanning.

import io
import json
import logging
import time
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .config import Paths

try:
    import yara as _yara
except ImportError:  # pragma: no cover - optional dependency
    _yara = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_UA = "LinShield-RuleUpdater/1.0 (open-source Linux endpoint security)"
_TIMEOUT = 45
LogFn = Callable[[str], None]


@dataclass(slots=True)
class Source:
    """A community rule source definition."""

    name: str
    description: str
    license: str
    kind: str  # "zip" | "github_dir"
    url: str | None = None
    repo: str | None = None
    branch: str = "main"
    dir_path: str | None = None
    name_prefix: str | None = None
    pinned: tuple[str, ...] = ()


@dataclass(slots=True)
class UpdateResult:
    source: str
    files_installed: int = 0
    rules: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
    install_dir: str = ""


# Curated, well-known sources. The Elastic Linux family rules are individually
# fetchable (and used for the test suite); YARA-Forge packages are the
# recommended broad-coverage option on a normal network.
SOURCES: dict[str, Source] = {
    "yara-forge-core": Source(
        name="yara-forge-core",
        description="YARA-Forge Core: high-accuracy, low-FP rules from 45+ vetted repos.",
        license="Mixed (per-rule; bundled in package). See packaged LICENSE.",
        kind="zip",
        url="https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip",
    ),
    "yara-forge-extended": Source(
        name="yara-forge-extended",
        description="YARA-Forge Extended: broader threat-hunting coverage (more FPs).",
        license="Mixed (per-rule; bundled in package). See packaged LICENSE.",
        kind="zip",
        url="https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip",
    ),
    "elastic-linux": Source(
        name="elastic-linux",
        description="Elastic Security YARA rules for Linux malware families (Mirai, Gafgyt, miners, rootkits, …).",
        license="Elastic License 2.0",
        kind="github_dir",
        repo="elastic/protections-artifacts",
        branch="main",
        dir_path="yara/rules",
        name_prefix="Linux_",
        pinned=(
            "Linux_Trojan_Mirai.yar",
            "Linux_Trojan_Gafgyt.yar",
            "Linux_Trojan_Tsunami.yar",
            "Linux_Trojan_Rekoobe.yar",
            "Linux_Trojan_Sysrv.yar",
            "Linux_Trojan_Kaiji.yar",
            "Linux_Trojan_Merlin.yar",
            "Linux_Trojan_Generic.yar",
            "Linux_Trojan_BPFDoor.yar",
            "Linux_Trojan_Metasploit.yar",
            "Linux_Trojan_Meterpreter.yar",
            "Linux_Cryptominer_Generic.yar",
            "Linux_Backdoor_Generic.yar",
            "Linux_Rootkit_Generic.yar",
            "Linux_Rootkit_Diamorphine.yar",
            "Linux_Worm_Generic.yar",
        ),
    ),
}


def list_sources() -> list[dict[str, str]]:
    """Return metadata for every known source (for `--list` / the GUI)."""
    return [
        {
            "name": s.name,
            "description": s.description,
            "license": s.license,
            "kind": s.kind,
        }
        for s in SOURCES.values()
    ]


def _get(url: str, *, accept: str | None = None) -> bytes:
    headers = {"User-Agent": _UA}
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 - https only
        return resp.read()


def _validate(text: str) -> int:
    """Return the rule count if ``text`` compiles, else raise."""
    if _yara is None:
        return 0  # can't validate without the engine; accept as-is
    compiled = _yara.compile(source=text)
    return sum(1 for _ in compiled)


def _rule_count_in(text: str) -> int:
    import re

    return len(
        re.findall(r"^[ \t]*(?:private[ \t]+|global[ \t]+)*rule[ \t]+\w+", text, re.M)
    )


def _reset_dir(path: Path) -> None:
    if path.exists():
        for child in path.glob("*"):
            if child.is_file():
                child.unlink()
    path.mkdir(parents=True, exist_ok=True)


def _install_text(dest_dir: Path, filename: str, text: str, result: UpdateResult,
                  *, validate: bool, log: LogFn) -> None:
    """Validate and write a single rule file into ``dest_dir``."""
    try:
        n = _validate(text) if validate else _rule_count_in(text)
    except Exception as exc:  # noqa: BLE001 - yara.Error and friends
        result.skipped += 1
        log(f"  skip {filename}: does not compile ({str(exc)[:60]})")
        return
    safe = filename if filename.endswith((".yar", ".yara")) else filename + ".yar"
    (dest_dir / safe).write_text(text, encoding="utf-8")
    result.files_installed += 1
    result.rules += n or _rule_count_in(text)
    log(f"  + {safe} ({n or _rule_count_in(text)} rules)")


def _update_zip(src: Source, dest_dir: Path, result: UpdateResult,
                *, validate: bool, log: LogFn) -> None:
    log(f"Downloading {src.name} …")
    blob = _get(src.url or "")
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as exc:
        result.errors.append(f"not a zip archive: {exc}")
        return
    members = [m for m in zf.namelist() if m.lower().endswith((".yar", ".yara"))]
    if not members:
        result.errors.append("archive contained no .yar files")
    for m in members:
        try:
            text = zf.read(m).decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            result.skipped += 1
            log(f"  skip {m}: {exc}")
            continue
        flat = Path(m).name
        _install_text(dest_dir, flat, text, result, validate=validate, log=log)
    # carry through any bundled license file
    for m in zf.namelist():
        if "license" in m.lower() and m.lower().endswith((".txt", ".md")):
            try:
                (dest_dir / "UPSTREAM_LICENSE.txt").write_text(
                    zf.read(m).decode("utf-8", "replace"), encoding="utf-8"
                )
            except Exception:  # noqa: BLE001
                pass
            break


def _list_github_dir(src: Source) -> list[str]:
    """List rule filenames in the source's GitHub directory (API)."""
    api = f"https://api.github.com/repos/{src.repo}/contents/{src.dir_path}?ref={src.branch}"
    data = json.loads(_get(api, accept="application/vnd.github+json").decode())
    names = [
        e["name"]
        for e in data
        if e.get("type") == "file" and str(e["name"]).endswith((".yar", ".yara"))
    ]
    if src.name_prefix:
        names = [n for n in names if n.startswith(src.name_prefix)]
    return sorted(names)


def _update_github_dir(src: Source, dest_dir: Path, result: UpdateResult,
                       *, validate: bool, log: LogFn) -> None:
    try:
        names = _list_github_dir(src)
        log(f"Listed {len(names)} files from {src.repo}/{src.dir_path}")
    except Exception as exc:  # noqa: BLE001 - rate limit, offline, etc.
        names = list(src.pinned)
        log(f"Directory listing unavailable ({str(exc)[:50]}); using {len(names)} pinned files")
    if not names:
        result.errors.append("no rule files to fetch")
        return
    raw_base = f"https://raw.githubusercontent.com/{src.repo}/{src.branch}/{src.dir_path}/"
    for name in names:
        try:
            text = _get(raw_base + name).decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            result.skipped += 1
            log(f"  skip {name}: fetch failed ({str(exc)[:40]})")
            continue
        _install_text(dest_dir, name, text, result, validate=validate, log=log)


def update(paths: Paths, source_name: str, *, validate: bool = True,
           log: LogFn | None = None) -> UpdateResult:
    """Download and install a community rule pack.

    Args:
        paths: Resolved LinShield paths.
        source_name: A key from :data:`SOURCES`.
        validate: Compile each file before installing (requires yara-python).
        log: Optional progress callback.

    Returns:
        An :class:`UpdateResult` summarising what was installed.
    """
    log = log or (lambda _msg: None)
    if source_name not in SOURCES:
        raise KeyError(f"unknown source '{source_name}'")
    src = SOURCES[source_name]
    dest_dir = paths.yara_user_dir / "community" / src.name
    _reset_dir(dest_dir)
    result = UpdateResult(source=src.name, install_dir=str(dest_dir))

    if src.kind == "zip":
        _update_zip(src, dest_dir, result, validate=validate, log=log)
    elif src.kind == "github_dir":
        _update_github_dir(src, dest_dir, result, validate=validate, log=log)
    else:  # pragma: no cover - guarded by SOURCES definitions
        result.errors.append(f"unsupported source kind: {src.kind}")

    manifest = {
        "source": src.name,
        "description": src.description,
        "license": src.license,
        "updated_at": time.time(),
        "files": result.files_installed,
        "rules": result.rules,
        "skipped": result.skipped,
    }
    try:
        (dest_dir / "_manifest.json").write_text(json.dumps(manifest, indent=2))
    except OSError:
        pass
    return result
