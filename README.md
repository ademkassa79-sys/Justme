# Cyber Defense Arsenal

A self-hosted, defensive monitoring system: it watches a log file, flags
known attack patterns in real time, alerts you, and shows everything on
a live dashboard. Nothing in this codebase attacks, exploits, or harms
anything — it only detects and informs.

```
┌─────────────────────────────────────┐
│         Cyber Defense Arsenal         │
├─────────────────────────────────────┤
│  1. Log Collector  → watches a log file for new lines
│  2. Pattern Engine  → checks lines against known attack signatures
│                       (mapped to MITRE ATT&CK techniques)
│  3. Alert System    → notifies via Telegram / email, saves history
│  4. Dashboard        → live web UI showing detections in real time
└─────────────────────────────────────┘
```

## What it detects right now

| Pattern | Severity | MITRE ATT&CK |
|---|---|---|
| Failed SSH login | Low | T1110 Brute Force |
| Repeated failed SSH logins (brute force) | Critical | T1110 Brute Force |
| SQL injection attempt | High | T1190 Exploit Public-Facing App |
| Cross-site scripting (XSS) payload | Medium | T1190 Exploit Public-Facing App |
| Directory/path traversal | High | T1083 File and Directory Discovery |
| OS command injection | Critical | T1059 Command and Scripting Interpreter |
| Probe for sensitive files (.env, .git, id_rsa) | High | T1552 Unsecured Credentials |

All signatures live in `pattern_engine.py` — add new ones by appending
to the `SIGNATURES` list. No other file needs to change.

## Setup (same on every platform)

```bash
pip install -r requirements.txt   # use pip3 on some systems
```

Edit `config/config.json`:
- `log_source.path` — the log file to watch
- `telegram` — set `enabled: true` and fill in your bot token + chat ID to get instant alerts (create a bot via @BotFather)
- `email` — optional, same idea with SMTP

## Running it

### Linux (server / desktop)
```bash
python3 main.py
```
Point `log_source.path` at a real file, e.g. `/var/log/auth.log` (you'll
likely need `sudo` to read it) or your app's own log file.

To keep it running permanently, create a systemd service:
```ini
# /etc/systemd/system/cyberdefense.service
[Unit]
Description=Cyber Defense Arsenal
After=network.target

[Service]
WorkingDirectory=/path/to/cyber_defense_arsenal
ExecStart=/usr/bin/python3 main.py
Restart=always

[Install]
WantedBy=multi-user.target
```
Then: `sudo systemctl enable --now cyberdefense`

### Termux (Android)
```bash
pkg install python
pip install -r requirements.txt
python main.py
```
Works the same way — Termux runs standard Python fine. Background
execution is limited by Android battery optimization, so for true 24/7
monitoring a small VPS (see "hosting" below) is more reliable than a
phone.

### Windows / macOS (as a desktop program)
```bash
python main.py
```
To turn it into a standalone `.exe` you can double-click, without
needing Python installed:
```bash
pip install pyinstaller
pyinstaller --onefile --add-data "config;config" --add-data "dashboard;dashboard" main.py
```

### Hosting it on a server / VPS
Same as the Linux instructions above. Any cheap VPS (even a free tier)
is enough for the log analysis + alerts. Just make sure port 5000 (or
whatever you set in `config.json`) is reachable if you want to view the
dashboard remotely — put it behind a reverse proxy (nginx) with HTTPS
and a login if it's exposed to the internet.

### As a website (dashboard only, viewed from anywhere)
The dashboard is already a normal Flask web app — once `main.py` is
running on a server, open `http://your-server-ip:5000` from any
browser, phone or desktop, no extra packaging needed.

### As a mobile app (APK)
Don't try to run the whole monitoring engine inside a phone app — Android
restricts background processes and low-level network access too much
for this to work reliably. Instead: run `main.py` on a server (VPS or
home Linux box), then wrap the dashboard URL in a minimal WebView app
(e.g. with Capacitor) to get a real APK that just shows your live
dashboard with push notifications. Ask if you want help building that
wrapper once the server side is running.

## Testing it safely (no real attack needed)

```bash
# Terminal 1 — generate realistic synthetic log traffic
python3 test/sample_log_generator.py

# config/config.json -> log_source.path should point to data/sample.log

# Terminal 2 — run the system
python3 main.py
```
Then open `http://localhost:5000` and watch detections appear live as
the generator writes synthetic suspicious lines.

## Design choices worth knowing

- **Detection only, no auto-blocking.** The system never bans an IP or
  kills a process by itself. That keeps a human in the loop before
  anything gets blocked — add that as a deliberate next layer if you
  want it (`integration/incident_responder.py` is the natural place).
- **Portable core.** `log_collector.py`, `pattern_engine.py`, and
  `alert_system.py` use only the Python standard library plus
  `requests`, so the same code runs unchanged on Linux, Termux,
  Windows, and macOS.
- **Pluggable log sources.** Swap `FileLogSource` for another class
  (journald, Windows Event Log, a syslog socket) without touching the
  Pattern Engine, Alert System, or Dashboard.

## Next layers (from the original roadmap)

This build covers the 4 core layers you asked for first. The earlier
full architecture sketch (anomaly detection with ML, vulnerability
scanning, honeypots, SIEM integration, sandboxing) is a reasonable
long-term roadmap, but each of those is its own multi-week project —
best added one at a time on top of this working foundation, not built
as empty scaffolding all at once.
