"""Tests for the community rule updater.

Network access is stubbed so these run hermetically and deterministically:
``_get`` is monkeypatched to return canned rule text / a synthetic zip.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from linshield.core import updater
from linshield.core.config import Paths

GOOD_RULE = 'rule Updater_Sample { strings: $a = "uniq-marker-xyz" condition: $a }'
BAD_RULE = "rule broken { condition }"


@pytest.fixture()
def paths(tmp_path: Path) -> Paths:
    p = Paths(config_dir=tmp_path / "config", data_dir=tmp_path / "data")
    p.ensure()
    return p


def test_list_sources_has_known_entries() -> None:
    names = {s["name"] for s in updater.list_sources()}
    assert "yara-forge-core" in names
    assert "elastic-linux" in names
    for s in updater.list_sources():
        assert s["license"]  # every source documents its license


def test_github_dir_update_installs_and_validates(paths: Paths, monkeypatch) -> None:
    # Stub the directory listing AND the raw file fetches.
    def fake_get(url: str, *, accept: str | None = None) -> bytes:
        if "api.github.com" in url:
            return b'[{"type":"file","name":"Linux_Good.yar"},{"type":"file","name":"Linux_Bad.yar"}]'
        if url.endswith("Linux_Good.yar"):
            return GOOD_RULE.encode()
        if url.endswith("Linux_Bad.yar"):
            return BAD_RULE.encode()
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(updater, "_get", fake_get)
    result = updater.update(paths, "elastic-linux", validate=True)

    # Good rule installed, broken rule skipped — never raises.
    assert result.files_installed == 1
    assert result.skipped == 1
    assert result.rules >= 1
    installed = list((paths.yara_user_dir / "community" / "elastic-linux").glob("*.yar"))
    assert [p.name for p in installed] == ["Linux_Good.yar"]
    assert (paths.yara_user_dir / "community" / "elastic-linux" / "_manifest.json").exists()


def test_github_dir_falls_back_to_pinned_on_listing_failure(paths: Paths, monkeypatch) -> None:
    calls = {"raw": 0}

    def fake_get(url: str, *, accept: str | None = None) -> bytes:
        if "api.github.com" in url:
            raise RuntimeError("403 rate limited")
        calls["raw"] += 1
        return GOOD_RULE.encode()

    monkeypatch.setattr(updater, "_get", fake_get)
    result = updater.update(paths, "elastic-linux", validate=True)
    # Falls back to the pinned file list rather than failing.
    assert result.files_installed == len(updater.SOURCES["elastic-linux"].pinned)
    assert calls["raw"] == result.files_installed


def test_zip_update_extracts_rules(paths: Paths, monkeypatch) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("packages/core/rules.yar", GOOD_RULE)
        zf.writestr("LICENSE.txt", "Upstream license text")
        zf.writestr("readme.md", "not a rule")
    blob = buf.getvalue()

    monkeypatch.setattr(updater, "_get", lambda url, accept=None: blob)
    result = updater.update(paths, "yara-forge-core", validate=True)
    assert result.files_installed == 1
    assert result.rules >= 1
    pack = paths.yara_user_dir / "community" / "yara-forge-core"
    assert (pack / "rules.yar").exists()
    assert (pack / "UPSTREAM_LICENSE.txt").exists()


def test_update_then_engine_loads_community_rules(paths: Paths, monkeypatch, tmp_path: Path) -> None:
    from linshield.core import Engine

    monkeypatch.setattr(updater, "_get", lambda url, accept=None: GOOD_RULE.encode()
                        if "api.github.com" not in url else b'[{"type":"file","name":"Linux_X.yar"}]')
    eng = Engine(paths=paths)
    try:
        before = eng.signatures.yara_rule_count
        eng.update_rules("elastic-linux")
        after = eng.signatures.yara_rule_count
        assert after > before  # recursive discovery picked up the community pack

        # Scan target must live OUTSIDE LinShield's own (excluded) directories.
        target = tmp_path / "scan_me" / "marker.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("contains uniq-marker-xyz here")
        summary = eng.scan([str(target)], scan_type="custom")
        assert any(d.signature == "Updater_Sample" for d in summary.detections)
    finally:
        eng.close()


def test_unknown_source_raises(paths: Paths) -> None:
    with pytest.raises(KeyError):
        updater.update(paths, "does-not-exist")
