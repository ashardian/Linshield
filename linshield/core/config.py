"""Configuration and path management for LinShield.

Paths adapt to the effective user: running as root uses system locations
(``/etc/linshield``, ``/var/lib/linshield``) so the daemon and FIM baseline
are shared, while running as an unprivileged user falls back to XDG paths in
the home directory so the tool is fully usable without ``sudo``.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path


def _is_root() -> bool:
    return os.geteuid() == 0


def _xdg(var: str, default: Path) -> Path:
    value = os.environ.get(var)
    return Path(value) if value else default


@dataclass(slots=True)
class Paths:
    """Resolved on-disk locations used by every component."""

    config_dir: Path
    data_dir: Path

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.json"

    @property
    def database(self) -> Path:
        return self.data_dir / "linshield.db"

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def hash_db(self) -> Path:
        return self.data_dir / "signatures" / "hashes.json"

    @property
    def yara_user_dir(self) -> Path:
        return self.data_dir / "signatures" / "yara"

    @property
    def log_file(self) -> Path:
        return self.data_dir / "linshield.log"

    @property
    def token_file(self) -> Path:
        return self.data_dir / "gui.token"

    @classmethod
    def resolve(cls) -> "Paths":
        home = Path.home()
        if _is_root():
            return cls(
                config_dir=Path("/etc/linshield"),
                data_dir=Path("/var/lib/linshield"),
            )
        return cls(
            config_dir=_xdg("XDG_CONFIG_HOME", home / ".config") / "linshield",
            data_dir=_xdg("XDG_DATA_HOME", home / ".local" / "share") / "linshield",
        )

    def ensure(self) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.hash_db.parent.mkdir(parents=True, exist_ok=True)
        self.yara_user_dir.mkdir(parents=True, exist_ok=True)
        # Quarantine must never be world-accessible.
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.quarantine_dir, 0o700)
            os.chmod(self.data_dir, 0o700)
        except PermissionError:
            pass


def _default_quick_paths() -> list[str]:
    """Locations commonly abused by Linux malware, used for a quick scan."""
    home = str(Path.home())
    return [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        f"{home}/Downloads",
        f"{home}/.cache",
        f"{home}/.config/autostart",
        f"{home}/.local/bin",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/var/spool/cron",
    ]


def _default_realtime_paths() -> list[str]:
    home = str(Path.home())
    return [f"{home}/Downloads", "/tmp", "/var/tmp", "/dev/shm"]


def _default_excludes() -> list[str]:
    return [
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/var/lib/linshield",
        "/snap",
        "*.iso",
        "*.img",
        "*.vmdk",
    ]


def _default_fim_paths() -> list[str]:
    return [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
        "/etc/ld.so.preload",
        "/etc/hosts",
    ]


@dataclass(slots=True)
class Config:
    """User-tunable behaviour. Persisted as JSON in ``config.json``."""

    quick_scan_paths: list[str] = field(default_factory=_default_quick_paths)
    full_scan_roots: list[str] = field(default_factory=lambda: ["/"])
    realtime_paths: list[str] = field(default_factory=_default_realtime_paths)
    exclude: list[str] = field(default_factory=_default_excludes)
    fim_paths: list[str] = field(default_factory=_default_fim_paths)
    trusted_paths: list[str] = field(default_factory=list)
    # When True, only CONFIRMED/LIKELY findings are reported by default; the
    # low-confidence REVIEW tier (lone pattern/heuristic hits) is hidden.
    strict_mode: bool = False
    # Optional HTTP(S) endpoint the real-time monitor POSTs a JSON alert to on
    # detection (for server deployments). Empty = disabled.
    alert_webhook: str = ""

    max_file_size_mb: int = 256
    follow_symlinks: bool = False
    scan_archives: bool = False

    use_hashes: bool = True
    use_yara: bool = True
    use_clamav: bool = True
    use_heuristics: bool = True

    auto_quarantine: bool = False
    realtime_auto_quarantine: bool = False

    gui_host: str = "127.0.0.1"
    gui_port: int = 8920

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> "Config":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in raw.items() if k in known}
        return cls(**filtered)  # type: ignore[arg-type]


def load_config(paths: Paths) -> Config:
    """Load config from disk, creating defaults on first run."""
    paths.ensure()
    if paths.config_file.exists():
        try:
            raw = json.loads(paths.config_file.read_text(encoding="utf-8"))
            return Config.from_dict(raw)
        except (json.JSONDecodeError, OSError):
            # Corrupt config should not brick the tool; fall back to defaults.
            return Config()
    cfg = Config()
    save_config(paths, cfg)
    return cfg


def save_config(paths: Paths, config: Config) -> None:
    paths.ensure()
    paths.config_file.write_text(
        json.dumps(config.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
    )
