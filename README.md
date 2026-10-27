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
- JSON data files (`threat_intel.json`, `fleet_consensus.json`, `blocklist.json`, `osint_grid.json`)

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