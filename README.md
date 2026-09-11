# Ransomware Behavior Detector

A lightweight, host-based ransomware detection tool written in Python. Instead of relying on file signatures, it watches for the *behaviors* ransomware exhibits while it runs — mass file encryption, bulk renaming, backup/shadow-copy deletion, and suspicious process spawning — and responds with logging, optional email alerts, and (when enabled) process termination.

## Why behavior-based detection

Signature-based AV struggles against novel or packed ransomware. Most ransomware families, regardless of variant, still have to do a small set of observable things on disk and in the process tree:

- Overwrite files with encrypted (high-entropy) content
- Rename large numbers of files to unfamiliar extensions in a short window
- Delete or disable local backups and shadow copies to block recovery
- Get initial execution via a document macro spawning a shell/interpreter

This tool watches for each of those signals independently and correlates them through a shared incident responder.

## Architecture

**Detectors** (`detect_ransomware.py`)

| Component | Watches for | Mapped to |
|---|---|---|
| `EntropyLogger` | Shannon entropy of newly written/modified files ≥ 7.5 | T1486 – Data Encrypted for Impact |
| `ExtensionLogger` | 5+ files renamed to an unrecognized extension within a 10s window | T1486 – Data Encrypted for Impact |
| `BackupLogger` | Processes running backup/snapshot-deletion commands (`lvremove`, `zfs destroy`, `restic forget`, `crontab -r`, etc.) or wiping known backup paths | T1490 – Inhibit System Recovery |
| `ProcessTreeLogger` | Office/PDF/mail apps (e.g. `soffice.bin`, `acroread`, `thunderbird`) spawning a shell or interpreter (`bash`, `python`, `powershell`-style) | T1204 – User Execution → T1059 – Command and Scripting Interpreter |

**Response** (`detect_ransomware.py`)

- `IncidentResponder` — central point all detectors report to. Decides whether to kill a process (gated by `dry_run`) and whether to send an alert (gated by a per-key cooldown so one incident doesn't spam the inbox).
- `AlertMailer` — sends email via SMTP (Gmail SMTP + App Password by default).

**Entry point** (`main.py`)

Wires the detectors to a single shared `IncidentResponder`, starts a `watchdog` filesystem observer on the target directory, and polls process state (`BackupLogger`, `ProcessTreeLogger`) once per second.

```
                 ┌──────────────────┐
 filesystem ───▶│  ActivityLogger   │──┐
 events          │ (entropy + ext)  │  │
                 └──────────────────┘  │
                                        ▼
 process list ──▶ BackupLogger ────▶ IncidentResponder ──▶ log + AlertMailer (+ kill if not dry_run)
 process list ──▶ ProcessTreeLogger ─▶      ▲
                                        │
                                (single shared instance)
```

## Setup

**Dependencies**

```bash
pip install watchdog psutil python-dotenv
```

**Environment variables** (`.env` in the project root)

```
SMTP_APP_PASSWORD=your_gmail_app_password
ALERT_SENDER_EMAIL=your_sending_address@gmail.com
```

> Use a Gmail **App Password**, not your account password — plain login is blocked once 2FA is enabled. Generate one under Google Account → Security → App Passwords.

If both variables are set, the script prompts for a recipient address at startup; leave it blank to run without email alerts.

## Usage

```bash
python main.py
```

By default it watches `./ransomware_test` (edit `path_to_watch` in `main.py` for a real target directory). Console output and `ransomware_detector.log` both show detection activity, e.g.:

```
2026-09-11 10:02:14 [WARNING] HIGH ENTROPY: ./ransomware_test/report.docx.locked (7.91)
2026-09-11 10:02:14 [DEBUG] alert email sent: Ransomware Behavior Detected — File Activity
```

## Configuration

| Setting | Location | Default | Purpose |
|---|---|---|---|
| `ENTROPY_THRESHOLD` | module constant | `7.5` | Shannon entropy (bits/byte, max 8.0) above which a write is flagged |
| `SUSPICIOUS_PARENTS` / `SUSPICIOUS_CHILDREN` | module constants | office/mail apps → shells | Process-tree pairs treated as suspicious |
| `window_seconds` / `threshold` | `ExtensionLogger.__init__` | 10s / 5 files | Mass-rename detection window and trigger count |
| `alert_cooldown_seconds` | `IncidentResponder.__init__` | 30s | Minimum gap between repeat alerts for the same file/PID |
| `dry_run` | `IncidentResponder.__init__` | `True` | When `True`, logs what it *would* terminate instead of killing the process |

## Safety notes

- Ships with `dry_run=True` — no process is actually killed until you flip this explicitly, after you've validated detections against your own baseline (some legitimate tools trip the entropy or process-tree checks).
- `KNOWN_EXTENSIONS` in `ExtensionLogger` is a starter allowlist; tune it to your own file types to reduce false positives before enabling termination.

## Limitations / future work

- Entropy sampling only reads the first 8KB of a file — sufficient for most ransomware payloads but can miss encryption schemes that only touch file tails or headers differently.
- No Windows-specific shadow-copy (`vssadmin`) detection yet — `BackupLogger`'s suspicious-command list is Linux/macOS-oriented.
- Detection is host-local; no SIEM forwarding yet. Natural next step given the existing Splunk/Sysmon pipeline: forward `ransomware_detector.log` via a Universal Forwarder and build a correlating SPL dashboard alongside the brute-force detections.