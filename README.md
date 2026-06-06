# 🛡️ LinShield

**An open-source endpoint security suite for Linux — like Windows Defender, but for Linux, and fully scriptable.**

LinShield is a single, coherent defensive security tool with both a **command-line interface** and a **localhost web GUI** that share one detection engine. It runs on desktops and servers, as a normal user or as root, and degrades gracefully when optional components aren't installed.

It is built as a **triage and visibility** tool: it shows you what looks off so you can investigate — not something to delete files on blindly. A core design goal is that **false positives never cause panic** (see [Confidence tiers](#confidence-tiers)).

---

## Contents

- [Features](#features)
- [Installation](#installation)
- [Upgrading](#upgrading)
- [Quick start](#quick-start)
- [Confidence tiers](#confidence-tiers)
- [How detection works](#how-detection-works)
- [Community rule packs](#community-rule-packs)
- [Trusted paths (allowlist)](#trusted-paths-allowlist)
- [CLI reference](#cli-reference)
- [Web GUI](#web-gui)
- [Running as a service](#running-as-a-service-systemd)
- [File locations](#file-locations)
- [Development](#development)
- [Security & scope](#security--scope)
- [License](#license)

---

## Features

| Capability | What it does |
|---|---|
| **Multi-engine scanning** | Layered detection: SHA-256 hash signatures → YARA rules → ClamAV (optional) → heuristics. Cheapest engines run first and short-circuit on a confirmed hit. |
| **Confidence tiers** | Every file is scored **Confirmed / Likely / Review** by corroborating engine signals, so a single fuzzy pattern match is never presented as a definitive conviction. |
| **Quarantine vault** | Files are moved to a locked `0700` vault (`chmod 000`), with full restore/delete and original-permission tracking. Auto-quarantine only ever touches the *Confirmed* tier. |
| **Real-time protection** | A `watchdog`-based monitor watches chosen directories and scans files as they're written. **Auto-quarantine is opt-in and off by default**, and even when on only ever acts on the *Confirmed* tier. Fires desktop notifications (`notify-send`) and an optional webhook on detection. |
| **Archive scanning** | Optionally looks inside `zip`/`jar`/`apk`/`tar`/`tar.gz` containers — including one level of **nested** archives — with zip-bomb guards. |
| **Rootkit / IOC sweep** | Checks `ld.so.preload` hijacks, 40+ known rootkit paths, hidden PIDs, promiscuous interfaces, suspicious listeners, **processes running from deleted executables** (fileless-malware tell), and **kernel taint** flags. |
| **File Integrity Monitoring (FIM)** | Hash baseline of critical files; reports additions, modifications, **permission and ownership (uid/gid) changes**, and deletions. |
| **Firewall status** | Read-only detection of the active backend (ufw / firewalld / nftables / iptables), even when the binaries live in `sbin` dirs off your PATH. |
| **Community rule updater** | Pulls curated open-source YARA rule packs (YARA-Forge, Elastic Linux rules) on demand, like `freshclam` for ClamAV. |
| **Trusted-path allowlist** | Mark paths you vouch for (your own tooling, exploit collections) so they're never scanned or flagged. |
| **Forensic reports** | Export the full security posture as JSON or a self-contained HTML report. |
| **CLI + Web GUI** | Everything works headless from the terminal; the GUI is a localhost-only dashboard with per-session token auth. |

LinShield ships with a built-in **EICAR** test signature so you can verify detection works immediately and safely.

---

## Installation

LinShield needs **Python 3.10+**.

```bash
unzip linshield-1.0.8.zip
cd linshield-1.0.8

# Recommended: virtualenv (clean, conflict-free, no sudo)
python3 -m venv .venv
source .venv/bin/activate
pip install ".[full]"          # CLI + GUI + YARA engine + rich output
```

Or use the installer, which handles Debian/Kali's externally-managed Python and optional systemd setup:

```bash
sudo ./install.sh
```

> On Debian/Kali, installing into system Python triggers PEP 668
> (`externally-managed-environment`). Use the virtualenv above, or `install.sh`,
> which passes `--break-system-packages` for you and reinstalls **only**
> LinShield (never your apt-managed dependencies).

### Optional external components

Auto-detected; LinShield works without them but gains capability if present:

- **ClamAV** (`clamscan` / `clamdscan`) — adds a full AV engine:
  `sudo apt install clamav clamav-daemon && sudo freshclam`
- **YARA** — installed automatically with the `[full]` or `[yara]` extra (`yara-python`).

---

## Upgrading

A plain `pip install .` over an existing install may report "already satisfied" and **not replace the files**. To upgrade cleanly:

```bash
pip install --force-reinstall ".[full]"
# or: pip uninstall linshield -y && pip install ".[full]"
```

Then **hard-refresh the browser** the first time you open the console (Ctrl+Shift+R / Cmd+Shift+R) or use a private window — the console version-stamps its assets and sends `no-store` headers, so this is only needed once when moving from an older build. Confirm with `linshield --version`; the sidebar shows the same version.

---

## Quick start

```bash
linshield status                 # engine status + which detection layers are active
linshield scan --quick           # quick scan of common malware hotspots
linshield scan ~/Downloads       # scan a specific folder
linshield gui                    # launch the localhost dashboard (opens your browser)
```

### ✅ Verify detection with EICAR (safe)

EICAR is the industry-standard, completely harmless antivirus test string.

```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
linshield scan /tmp/eicar.com    # flagged CONFIRMED via hash; exits 2
rm /tmp/eicar.com
```

---

## Confidence tiers

No detection method gives broad coverage with zero false positives — that's the central tension in *all* antivirus software, not a LinShield quirk. Hash and ClamAV matches are definitive but only catch known samples; YARA and heuristics catch the unknown but *will* sometimes misfire on benign files (security tools, installers, source code).

So rather than flashing a scary red "INFECTED" for a single fuzzy match, LinShield assigns every file a **confidence tier** by corroborating the engine signals:

| Tier | Meaning | Auto-quarantined? |
|---|---|---|
| 🔴 **Confirmed** | Definitive — exact hash match or ClamAV. | **Yes** |
| 🟠 **Likely** | Independent engines agree, or a high-specificity rule (e.g. a reverse shell). Worth investigating. | No |
| 🔵 **Review** | A single pattern/heuristic hit. **Frequently a false positive.** Informational only. | No |

What this guarantees:

- **Auto-quarantine only ever touches the Confirmed tier.** A `curl … | bash` installer or a YARA hit on your own script lands in *Review* and is never silently moved or deleted.
- Scan summaries lead with the Confirmed count; Review items appear in a calm, clearly-labelled section with a "frequently false positive" note — not as red threats.
- `linshield scan` exits `2` for Confirmed, `1` for Likely, `0` otherwise — so CI and scripts don't treat a low-confidence hint as a failure.
- **Strict mode** (Settings → Strict mode, or `strict_mode` in config) hides the Review tier entirely, for a near-false-positive-free experience showing only Confirmed and Likely.

---

## How detection works

1. **Hashes** — fast exact match against a known-bad SHA-256 database (seeded with EICAR).
2. **YARA** — bundled defensive rules plus any rules in your config's `yara/` directory and downloaded community packs.
3. **ClamAV** — if installed, files are also passed to `clamdscan`/`clamscan`.
4. **Heuristics** — structural/behavioural checks: ELF binaries in temp dirs, unexpected SUID/SGID, hidden ELF dotfiles, world-writable executables, and risky code patterns (`curl … | bash`, `/dev/tcp` reverse shells, `nc -e`, etc.).

### Precision: avoiding false positives

LinShield's bundled rules are tuned for **precision over recall**:

- **Binaries and archives are excluded from shell/script rules.** A `.exe`, `.apk`, `.zip` or ELF that merely contains the bytes `curl` or `|sh` is not flagged by the script rules (compiled-malware rules like the cryptominer and reverse-shell signatures still run everywhere).
- **Patterns must be contiguous** — the downloader rule needs the download and the pipe-to-shell on the same command line, not the two tokens anywhere in the file.
- **YARA rule files (`.yar`/`.yara`) are never YARA-scanned** — they're signature *data* and would self-match.
- **LinShield's own files are exempt** via a built-in self-exclusion marker, so scanning the install/source tree won't flag the tool itself.
- **LinShield's own storage** (data, config, quarantine, rule packs) is always excluded from scans.

You can also add your own high-confidence signatures:

```bash
linshield signatures add-hash <sha256> "Custom.Malware.Name"
linshield signatures import-hashes feed.csv      # bulk import
```

`import-hashes` accepts a plain one-hash-per-line list or a **MalwareBazaar**-style CSV export (any 64-hex token on a line is taken as the SHA-256; an adjacent label becomes the detection name). The hash DB is plain JSON, so you can also populate it directly:

```json
{ "<sha256>": { "name": "Trojan.Linux.Example", "severity": "high" } }
```

Free hash feeds: [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch) publishes CSV exports you can import directly.

---

## Community rule packs

The bundled rules are deliberately small and precise. For real-world coverage, pull curated open-source packs with the updater (network required):

```bash
linshield update --list            # show available sources
linshield update yara-forge-core   # recommended: high-accuracy, low-FP (45+ repos)
linshield update elastic-linux     # Elastic's Linux malware family rules
```

Or in the GUI: **Tools → Community Rule Packs → Update Rules**.

Sources:

- **yara-forge-core / yara-forge-extended** — [YARA-Forge](https://yarahq.github.io/) packages aggregating 45+ vetted repositories, quality-scored and deduplicated. *Core* is tuned for low false positives; *Extended* trades some FPs for broader coverage.
- **elastic-linux** — [Elastic Security](https://github.com/elastic/protections-artifacts) YARA rules for Linux malware families (Mirai, Gafgyt, Tsunami, cryptominers, rootkits including Diamorphine, Metasploit/Meterpreter, and more).

These third-party rules are **not redistributed** inside LinShield (which is MIT-licensed). They're downloaded on demand into your user rules directory, where the **upstream license applies**. Every downloaded file is compiled and validated before activation; any file that fails to compile is skipped so a bad rule can never disable the engine.

---

## Trusted paths (allowlist)

Security tooling, exploit collections and your own scripts legitimately contain malware-like patterns (`curl … | bash`, reverse-shell snippets, etc.). To silence a path you vouch for:

```bash
linshield trust ~/tools          # never scan or flag anything under here
linshield trust --list
linshield trust --remove ~/tools
```

You can also click **Trust** next to any scan result in the GUI, or edit **Settings → Trusted Paths**. Trusted paths are skipped entirely — identical files *outside* a trusted path are still scanned, so the allowlist is precise rather than a global mute.

---

## CLI reference

```
linshield [--verbose] COMMAND [ARGS]
```

| Command | Description |
|---|---|
| `scan [PATHS]…` | Scan paths. Flags: `--quick`, `--full`, `--no-recursive`, `--quarantine`, `--json`, `--min-severity {info,low,medium,high,critical}`. Exits `2`=Confirmed, `1`=Likely, `0`=otherwise. |
| `monitor` | Start real-time protection in the foreground. |
| `quarantine list` | List quarantined items. |
| `quarantine restore <id>` | Restore a quarantined file to its original path. |
| `quarantine delete <id>` | Permanently delete a quarantined file. |
| `rootkit` | Run the rootkit / IOC sweep. |
| `fim init` | Build the file-integrity baseline. |
| `fim check` | Check tracked files against the baseline. |
| `firewall` | Show the host firewall status. |
| `status` | Show engine status, paths and counts. |
| `history` | Show recent scans and detections. |
| `signatures add-hash <sha256> <name>` | Add a custom hash signature. |
| `signatures import-hashes <file>` | Bulk-import SHA-256 hashes from a plain list or MalwareBazaar CSV export (`--name` sets the default label). |
| `signatures reload` | Reload signature databases. |
| `config validate` | Check that `config.json` parses and has no unknown keys. |
| `update [SOURCE]` | Download community YARA rule packs (`--list` to see sources). |
| `trust [PATH]` | Manage the trust allowlist (`--list`, `--remove PATH`). |
| `report --output FILE [--format json\|html]` | Write a forensic report. |
| `gui [--host H] [--port P] [--no-browser]` | Launch the web dashboard. |

Examples:

```bash
linshield scan --full --json > scan.json     # machine-readable full scan
linshield fim init && linshield fim check     # baseline, then verify integrity
linshield report --format html -o report.html # forensic HTML report
linshield update yara-forge-core              # broaden detection coverage
```

---

## Web GUI

```bash
linshield gui
```

- Binds to **127.0.0.1** only (never exposed to the network).
- Generates a **one-time session token** on every launch; the URL printed in your terminal carries it and sets a secure, `HttpOnly` cookie.

Tabs and what you can do:

- **Dashboard** — protection status, all-time counts, engine/perimeter chips, and a **Real-Time Protection master switch** with live scanned/detected/quarantined counters.
- **Scan** — quick/full/custom scans with live progress; results grouped into **Confirmed / Likely / Review** tiers. Each row has **Trust** and (for Confirmed/Likely) **Quarantine** actions, plus **Quarantine all**.
- **Quarantine** — restore or permanently delete isolated files.
- **History** — recent scans, the detection log, and the event stream.
- **Tools** — rootkit sweep, FIM, firewall, and **Signature Management**: update community rule packs, import/remove your own YARA rules (validated before saving), add custom hash signatures, reload signatures.
- **Settings** — engine toggles, behaviour (auto-quarantine, archive scanning, **strict mode**), per-profile scan paths, real-time watch paths, FIM paths, exclusions, **trusted paths**, max file size, and the web-console bind host/port.

Change the bind address/port with `linshield gui --host 127.0.0.1 --port 9000 --no-browser`.

---

## Running as a service (systemd)

Unit files live in `packaging/`:

```bash
sudo cp packaging/linshield-monitor.service /etc/systemd/system/
sudo cp packaging/linshield-scan.service packaging/linshield-scan.timer /etc/systemd/system/
sudo cp packaging/linshield-update.service packaging/linshield-update.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now linshield-monitor.service   # real-time daemon
sudo systemctl enable --now linshield-scan.timer        # daily scheduled scan
sudo systemctl enable --now linshield-update.timer      # weekly YARA rule refresh
```

`install.sh` can place and enable all of these for you. For server alerting, set
`alert_webhook` in the config (or **Settings → Alert Webhook** in the GUI) to
receive a JSON POST on every real-time detection.

---

## File locations

LinShield adapts to who runs it:

| | Run as **root** | Run as **user** |
|---|---|---|
| Config | `/etc/linshield/` | `~/.config/linshield/` |
| Data / DB / quarantine / rules | `/var/lib/linshield/` | `~/.local/share/linshield/` |

These directories are always excluded from scanning.

---

## Development

```bash
pip install ".[dev]"
pytest                 # run the test suite (46 tests)
ruff check linshield   # lint
black linshield        # format
mypy linshield         # type-check
```

### Changelog highlights (1.0.8)

- Confidence tiers now drive real-time protection too: auto-quarantine is **off by default** and only ever acts on *Confirmed* detections.
- FIM tracks **ownership (uid/gid)** changes; rootkit sweep adds **deleted-executable process** and **kernel-taint** checks plus a 40+ entry path list.
- New `signatures import-hashes` (MalwareBazaar CSV / plain list), `config validate`, and `scan --min-severity`.
- Desktop notifications and an optional server **alert webhook** on real-time detection.
- **Nested** archive scanning (one level deep) and a weekly `linshield-update.timer`.

---

## Security & scope

LinShield is a **defensive** tool. Quarantine actions are reversible, firewall inspection is read-only, the GUI is localhost-only with per-session tokens, and nothing below the Confirmed tier is ever auto-actioned. No detection tool eliminates false positives — LinShield's job is to surface what's worth a human's attention without crying wolf, and to make acting on findings a deliberate choice.

## License

MIT — see [LICENSE](LICENSE). Third-party rule packs downloaded via `linshield update` retain their own upstream licenses. Contributions welcome.
