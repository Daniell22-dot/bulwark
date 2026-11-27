# Bulwark Static Site

![Bulwark](https://img.shields.io/badge/Bulwark-website-important?style=for-the-badge) ![Python](https://img.shields.io/badge/Python-3.13-important?style=for-the-badge) ![PHP2Shell](https://img.shields.io/badge/PHP2Shell-security-important?style=for-the-badge) ![C-Sharp](https://img.shields.io/badge/C%23-.NET-important?style=for-the-badge) ![YARA](https://img.shields.io/badge/YARA-rule-important?style=for-the-badge)

A static website for the Bulwark security platform. Provides vulnerability assessment pages, ATT&CK coverage maps, and PHP2Shell detection resources. Content is generated from Python scripts and Markdown files, deployed via Vercel.

## Pages
- `index.html` – Home / overview
- `check.html` – Scanner UI
- `map.html` – ATT&CK coverage map
- `about.html`, `privacy.html`, `terms.html`, `pricing.html`, `features.html`, `reports.html`

## Data & Scripts
- `scripts/build-blocklist.py` – builds the public IP/domain blocklist snapshot.
- `scripts/build-osint.py` – builds CISA KEV, NVD, MITRE ATT&CK and optional provider summaries.
- `scripts/build-kenya-incidents.py` – builds the Kenya public-incident snapshot.
- `backend/threat_feeds.py` – ingests network threat feeds into JSON and a local SQLite database.
- `backend/fleet_consensus.py` – correlates threat-feed data with agent telemetry when its SQLite inputs are available.
- `backend/web_scanner.py` – scheduled web-security checks.
- `backend/app/main.py` – optional FastAPI service; it is not part of the static Vercel deployment.
- `scripts/export-live.ps1` – exports live-map data from the local console.

Generated snapshots are kept under `data/` and served as static files.

## Automation & Deployment

GitHub Actions runs the data-generation scripts on hosted runners, then commits changed snapshots to the repository. Vercel serves the static site and deploys those commits through its Git integration; Vercel does **not** run these Python scripts.

| Workflow | Runs | Schedule |
|---|---|---|
| `refresh-intel.yml` | `build-blocklist.py`, `build-osint.py` | Every 6 hours; manual dispatch |
| `threat-feeds.yml` | `backend/threat_feeds.py` | Every 6 hours; manual dispatch |
| `refresh-kenya-incidents.yml` | `build-kenya-incidents.py` | Daily; manual dispatch |
| `fleet-consensus.yml` | `backend/fleet_consensus.py` | After threat feeds and on a 6-hour schedule |
| `scheduled-scans.yml` | `backend/web_scanner.py` | Daily; manual dispatch |

The public blocklist/OSINT snapshots and Kenya incident snapshot are independent of the FastAPI backend. Optional `ABUSECH_AUTH_KEY`, `OTX_API_KEY`, and `ACLED_KEY`/`ACLED_EMAIL` are configured as GitHub repository secrets when those providers are enabled.

**Fleet-consensus caveat:** the workflow currently expects `data/threat_intel.db` and `data/telemetry.db`. SQLite files are git-ignored, and the scheduled feed job uploads its database only as an artifact; the GitHub runner therefore may not have fresh databases to correlate. The checked-in `fleet_consensus.json` can be empty or stale until its data handoff is designed. Do not solve this by committing raw telemetry: it can contain hostnames, IP addresses, and event details.

### SENTINEL is a separate application

`D:\SENTINEL` is the .NET 8 Windows endpoint product, not part of this static site. Its `Sentinel.ThreatIntel` service runs on a Windows machine and refreshes its own feeds while the service is running; its GitHub Actions workflow builds the Windows agent/installer on push or pull request. Neither that workflow nor Vercel runs the Python snapshot scripts above. The live site endpoints require the separately configured local services/tunnel described in `D:\SENTINEL\FREE-TOOLS-DEPLOY.md`.

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
- Python for scheduled data generation and backend processing
- YARA rules for malware pattern detection
- Vercel for static hosting
- Markdown content files

## Local Development
```bash
# Public snapshots (stdlib only; optional provider keys come from environment)
python scripts/build-blocklist.py
python scripts/build-osint.py
python scripts/build-kenya-incidents.py

# Network threat-feed ingestion (requires httpx)
python -m pip install httpx
python backend/threat_feeds.py

# Open index.html in a browser, or use a local static server.
```

To run the optional FastAPI service locally, see [backend/README.md](backend/README.md). It requires a separate Python environment and is not deployed by Vercel's static-site configuration.
