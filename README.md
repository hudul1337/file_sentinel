# File Sentinel

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)

**File Sentinel** is an automated, event-driven background watchdog service for local file systems. It monitors target directories (such as your Downloads folder), checks newly created or completed downloads against the **VirusTotal API** via SHA-256 hash lookups, and automatically quarantines or deletes malicious files based on configurable policies.

---

## Key Features

- **Real-Time Directory Monitoring:** Built on Python's native `watchdog` library for low-overhead filesystem event listening (`IN_CLOSE_WRITE` / `FileCreatedEvent`).
- **Smart Temp-File Handling:** Automatically defers scans while temporary download extensions (`.crdownload`, `.part`, `.tmp`, `*.download`) are active, executing the scan only when the download finalized state is reached.
- **SHA-256 Hash Scanning:** Queries VirusTotal by file signature—ensuring zero data exposure from uploading entire files to the public API.
- **Persistent SQLite Caching:** Caches SHA-256 scan results locally to minimize API calls, speed up repeated file handling, and conserve free-tier API quotas.
- **Resilient API Layer:** Features automatic exponential backoff and rate-limit handling (`HTTP 429`) to accommodate VirusTotal's public API constraints (4 requests/min).
- **Flexible Quarantine Engine:** Isolates suspicious files into a secure directory with restricted permissions, maintaining an append-only JSON Lines (`manifest.jsonl`) audit trail.
- **Multiple Operational Modes:**
  - `prompt`: Displays interactive GUI dialogs for user decision-making.
  - `quarantine`: Automatically moves flagged files without user interaction.
  - `delete`: Instantly removes malicious files (ideal for headless servers).
- **Cross-Platform Alerts:** Sends OS-native desktop notifications with automatic fallback to standard console logging in headless or SSH environments.

---

## Architecture & Workflow

```
[ New File Detected ] ──► [ Is Temp File? ] ──► (Wait until download finishes)
                               │
                               ▼
                    [ Compute SHA-256 Hash ]
                               │
                               ▼
                   [ Check SQLite Cache ]
                          /        \
                    (Hit)          (Miss)
                     /                \
    [ Apply Cached Result ]        [ VirusTotal API Lookup ]
                                       │
                                       ▼
                             [ Is Malicious Flagged? ]
                             /                     \
                         (Clean)                (Flagged)
                           /                       \
                     [ Cache & Pass ]        [ Notification Triggered ]
                                                   │
                                                   ▼
                                         [ Apply AUTO_ACTION ]
                                       ┌───────────┼───────────┐
                                       ▼           ▼           ▼
                                   [ Prompt ] [ Quarantine ] [ Delete ]
```

---

## Installation

### Prerequisites
* Python 3.9 or higher
* A free [VirusTotal API Key](https://www.virustotal.com/gui/join-us)

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/hudul1337/file_sentinel.git
   cd file-sentinel
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate

   # Windows
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment settings:**
   ```bash
   cp .env.example .env
   ```
   Open `.env` in your text editor and paste your VirusTotal API key:
   ```env
   VT_API_KEY=your_virustotal_api_key_here
   WATCH_DIR=~/Downloads
   QUARANTINE_DIR=~/Quarantine
   AUTO_ACTION=prompt
   LOG_LEVEL=INFO
   ```

---

## Usage

### Basic Execution

Run the script using your `.env` configuration defaults:

```bash
python main.py
```

### Advanced CLI Flags

Override `.env` settings directly via command-line arguments:

```bash
python main.py \
  --watch-dir ~/Downloads \
  --quarantine-dir ~/.file_sentinel/quarantine \
  --auto-action quarantine \
  --verbose
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--watch-dir` | Path | `~/Downloads` | Path to the directory monitored for new files. |
| `--quarantine-dir` | Path | `~/Quarantine` | Path where malicious files are isolated. |
| `--auto-action` | String | `prompt` | Response policy: `prompt`, `quarantine`, or `delete`. |
| `--verbose` | Flag | `False` | Enables debug level logging output. |

---

## Project Structure

```
file-sentinel/
├── main.py                    # CLI entry point and setup orchestration
├── file_sentinel/
│   ├── __init__.py
│   ├── config.py              # Environment variable loading & validation
│   ├── hashing.py              # Streaming SHA-256 calculator for large files
│   ├── cache.py                 # SQLite engine for scan history persistence
│   ├── virustotal.py           # VirusTotal API v3 client with backoff retries
│   ├── notifier.py              # OS desktop alerts & terminal fallback
│   ├── prompts.py               # Tkinter GUI prompts / interactive CLI response
│   ├── quarantine.py            # File moving, permission revoking & audit logging
│   └── watcher.py                # Watchdog handler & async workflow orchestration
├── tests/                     # Unit test suite
├── .env.example               # Example configuration template
├── requirements.txt           # Python dependencies
└── LICENSE                    # MIT License
```

---

## Audit Logs & Quarantine Manifest

Every action taken by File Sentinel is logged in two places:

1. **System Log:** Written to `~/.file_sentinel/file_sentinel.log` with automatic log rotation.
2. **Quarantine Manifest:** A JSON Lines log stored in `<quarantine-dir>/manifest.jsonl` tracking quarantined files, original paths, and hash records for recovery or auditing:

```json
{"timestamp": "2026-07-28T19:50:00Z", "original_path": "/Users/user/Downloads/invoice.exe", "quarantine_path": "/Users/user/Quarantine/20260728_invoice.exe", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "positives": 14, "total_engines": 72, "action": "quarantined"}
```

---

## Running as a Background Service (Linux systemd)

To run File Sentinel continuously in the background on Linux:

1. Create a service file:
   ```bash
   sudo nano /etc/systemd/system/file-sentinel.service
   ```

2. Add the following config (adjust paths accordingly):
   ```ini
   [Unit]
   Description=File Sentinel Watchdog Service
   After=network.target

   [Service]
   Type=simple
   User=yourusername
   WorkingDirectory=/path/to/file-sentinel
   ExecStart=/path/to/file-sentinel/.venv/bin/python main.py --auto-action quarantine
   Restart=on-failure
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   ```

3. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now file-sentinel
   ```

---

## Disclaimer

File Sentinel is a lightweight security layer utilizing VirusTotal's public API signature matching. It is **not** a replacement for full Endpoint Detection and Response (EDR) or real-time local antivirus engines. Free VirusTotal API keys carry rate limits (4 requests/min, 500 requests/day). Use responsibly.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.