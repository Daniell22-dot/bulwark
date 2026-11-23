# Bulwark Static Site

![Bulwark](https://img.shields.io/badge/Bulwark-website-important?style=for-the-badge) ![Python](https://img.shields.io/badge/Python-3.13-important?style=for-the-badge) ![PHP2Shell](https://img.shields.io/badge/PHP2Shell-security-important?style=for-the-badge) ![C-Sharp](https://img.shields.io/badge/C%23-.NET-important?style=for-the-badge) ![YARA](https://img.shields.io/badge/YARA-rule-important?style=for-the-badge)

A static website for the Bulwark security platform. Provides vulnerability assessment pages, ATT&CK coverage maps, and PHP2Shell detection resources. Content is generated from Python scripts and Markdown files, deployed via Vercel.

## Pages
- `index.html` – Home / overview
- `check.html` – Scanner UI
- `map.html` – ATT&CK coverage map
- `about.html`, `privacy.html`, `terms.html`, `pricing.html`, `features.html`, `reports.html`

## Data & Scripts
- `main.py` – Fleet data ingestion & SBOM generation
- `fleet_consensus.py` – Consensus filtering
- `threat_feeds.py` – Feed processing
- `web_scanner.py` – Web vulnerability scanning
- `build-blocklist.py` – Blocklist generation
- `export-live.ps1` – Live export script
- JSON data files (`threat_intel.json`, `fleet_consensus.json`, `blocklist.json`, `osint_grid.json`, `osint_sources.json`, `kenya_incidents.json`)

## Public OSINT sources
- `scripts/build-blocklist.py` pulls FireHOL, DShield, Feodo, Emerging Threats, Spamhaus DROP, Tor exit nodes, and optional abuse.ch URLhaus / AlienVault OTX indicators into `data/blocklist.json` and `data/blocklist.js`.
- `scripts/build-osint.py` pulls CISA KEV, NVD, MITRE ATT&CK, and optional abuse.ch ThreatFox / AlienVault OTX summaries into `data/osint_sources.json` and `data/osint_sources.js`.
- `backend/threat_feeds.py` merges network indicators from FireHOL, DShield, Feodo, Emerging Threats, Spamhaus DROP, and Tor into `data/threat_intel.json`.
- Optional keys: set `ABUSECH_AUTH_KEY` and `OTX_API_KEY` in the environment to enable authenticated feeds; unset feeds are skipped and previous snapshots are retained.
- `scripts/build-kenya-incidents.py` scans the last 24 hours of keyless GDELT Events 2.0 exports, filters Kenya-located material conflict, theft/property, cyber, protest and coercion reports, optionally merges ACLED Kenya events, and writes `data/kenya_incidents.json` and `data/kenya_incidents.js`.
- Optional Kenya source: set `ACLED_KEY` and `ACLED_EMAIL` in the environment or GitHub repository secrets to add ACLED Kenya event coverage; without them the daily snapshot uses GDELT Kenya only.
- `.github/workflows/refresh-kenya-incidents.yml` refreshes the Kenya incident snapshot daily and keeps the previous snapshot if the upstream feeds are unavailable.
- The live map labels these as public OSINT sources; only real Bulwark agent reports should be described as live fleet detections.

## Tech Stack
- HTML5 / CSS3 / JavaScript
- Python 3.13 for backend processing
- YARA rules for malware pattern detection
- Vercel for static hosting
- Markdown content files

## Local Development
```bash
python -m pip install -r requirements.txt
python main.py   # generate content
# Open index.html in browser
```