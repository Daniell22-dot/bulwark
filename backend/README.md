# Bulwark Backend (Python/FastAPI)

Cloud telemetry ingest + scheduled scans + GitHub Actions automation for the Bulwark website.

## Quick Deploy (Free Tier Options)

### Render (Recommended - Free Web Service)
1. Connect this repo to Render
2. New > Web Service > Docker
3. Dockerfile path: `backend/Dockerfile`
4. Add env vars:
   - `GITHUB_TOKEN` = repo-scoped PAT with `contents:write`
   - `GITHUB_REPO` = `your-org/bulwark`
   - `GITHUB_BRANCH` = `main`
5. Add persistent disk: `/app/data` (1 GB free)

### Fly.io
```bash
fly launch --dockerfile backend/Dockerfile
fly volumes create bulwark_data --size 1
fly secrets set GITHUB_TOKEN=... GITHUB_REPO=...
fly deploy
```

### Railway
- Connect repo > Add Service > Dockerfile > `backend/Dockerfile`
- Add volume for `/app/data`

## Local Dev
```bash
cd backend
pip install -r requirements.txt
export DATA_DIR=./data
uvicorn app.main:app --reload --port 8000
```

Test:
```bash
# Send test telemetry
curl -X POST http://localhost:8000/telemetry \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test-agent-001",
    "host": "DESKTOP-ABC",
    "ip": "192.168.1.50",
    "os": "Windows 11",
    "events": [
      {"type": "canary_trip", "severity": "critical", "message": "Credential canary triggered"},
      {"type": "etw_evasion", "severity": "high", "message": "ETW patching detected"}
    ]
  }'

# Get dashboard data
curl http://localhost:8000/api/dashboard
```

## GitHub Actions Setup

Add these repository secrets:
- `GITHUB_TOKEN` - auto-provided, but ensure workflow has `contents: write`
- `WEB_SCAN_TARGETS` - comma-separated URLs for scheduled web scans (e.g., `https://example.com,https://api.example.com`)

### Complete Workflow Suite

| Workflow | Schedule | Purpose |
|----------|----------|---------|
| `threat-feeds.yml` | Every 6h | Fetch FireHOL, DShield, Feodo, SSLBL, URLhaus → `data/threat_intel.json` |
| `fleet-consensus.yml` | After threat feeds | Correlate threat intel with agent telemetry → `data/fleet_consensus.json` |
| `refresh-intel.yml` | Every 6h | Build blocklist for `/check` page → `data/blocklist.json` |
| `scheduled-scans.yml` | Daily 02:00 UTC | Web vuln scan (HTTP, TLS, headers, Playwright deep scan) + repo secret scan |
| `telemetry-rollup.yml` | Hourly | Aggregate agent telemetry → `data/telemetry_summary.json` |
| `alert-check.yml` | Every 15 min | Create GitHub Issues on critical telemetry events |
| `fleet-consensus.yml` | After threat feeds | Correlate threat feeds with fleet sightings |
| `dependency-autopatch.yml` | Weekly Mon 03:00 | Detect vulns → branch → test → PR |
| `sast-container-iac.yml` | Weekly Sun 04:00 / PR | CodeQL SAST, Trivy container, tfsec/checkov IaC, TruffleHog secrets |
| `security-posture.yml` | Daily 06:00 UTC | Collect metrics, create GitHub Issues on critical findings |
| `security-posture.yml` | Daily 06:00 UTC | Security posture dashboard metrics |
| `dependency-autopatch.yml` | Weekly Mon 03:00 | Auto-patch vulnerable deps → test → PR |
| `sast-container-iac.yml` | Weekly / PR | CodeQL SAST, Trivy container, tfsec/checkov IaC, TruffleHog |
| `security-posture.yml` | Daily 06:00 UTC | Security posture dashboard + alerts |

### Required Repository Secrets
- `GITHUB_TOKEN` - auto-provided, ensure `contents: write` permission
- `WEB_SCAN_TARGETS` - comma-separated URLs (e.g., `https://example.com,https://api.example.com`)

### Optional Manual Triggers
All workflows support `workflow_dispatch` for manual runs. Some have inputs:
- `scheduled-scans.yml`: `deep_scan` (boolean) — enable Playwright deep scan
- `dependency-autopatch.yml`: `auto_merge` (boolean) — auto-merge PR if tests pass

## C# Agent Integration

In your C# agent, POST to `/telemetry`:

```csharp
var payload = new {
    agent_id = "bulwark-agent-" + Environment.MachineName,
    host = Environment.MachineName,
    ip = GetLocalIP(),
    os = Environment.OSVersion.ToString(),
    events = events.Select(e => new {
        type = e.Type,
        severity = e.Severity.ToString().ToLower(),
        message = e.Message,
        timestamp = DateTime.UtcNow.ToString("o"),
        metadata = e.Metadata
    })
};

await httpClient.PostAsJsonAsync("https://your-backend.onrender.com/telemetry", payload);
```

## Web Scanner (Playwright Deep Scan)

The scanner supports two modes:

**Fast mode** (default): HTTP-only checks — headers, TLS, cookies, tech fingerprinting, sensitive paths, forms, SRI.

**Deep scan** (`DEEP_SCAN=true` + `USE_PLAYWRIGHT=true`): Full Chromium rendering — DOM XSS sinks, rendered DOM forms, mixed content, console errors, network errors.

Enable via workflow input or env vars:
```yaml
env:
  USE_PLAYWRIGHT: true
  DEEP_SCAN: true
```

## Frontend Data Flow (No Backend Server Needed)

```
GitHub Actions (scheduled) → Fetch feeds → SQLite → JSON export → Commit to repo
                                                        ↓
                                          Frontend reads data/*.json (no API)
                                                        ↓
                                          Dashboard displays live stats
```

All dashboard data comes from JSON files in `data/` committed by workflows:
- `data/threat_intel.json` — raw threat feeds
- `data/fleet_consensus.json` — threat intel + fleet correlation
- `data/blocklist.json` — `/check` page blocklist
- `data/web_scan_latest.json` — web vulnerability scan results
- `data/telemetry_summary.json` — hourly agent telemetry rollup
- `data/fleet_consensus.json` — threat intel + fleet sightings
- `security_metrics.json` — daily security posture metrics

## Environment Variables

| Var | Required | Default | Description |
|-----|----------|---------|-------------|
| `DATA_DIR` | No | `./data` | SQLite/JSON storage path |
| `PORT` | No | `8000` | HTTP port |
| `GITHUB_TOKEN` | Yes* | - | PAT for committing data/creating issues |
| `GITHUB_REPO` | Yes* | - | `owner/repo` for sync |
| `GITHUB_BRANCH` | No | `main` | Target branch |
| `USE_PLAYWRIGHT` | No | `false` | Enable Playwright deep scan |
| `DEEP_SCAN` | No | `false` | Run Playwright deep scan |

*Required for GitHub sync/alerts. Omit if running standalone.

## Extending

Add routes in `app/routes/` and register in `app/main.py`. The pattern:
- Telemetry in = POST `/telemetry`
- Dashboard out = GET `/api/dashboard`
- Actions consume `data/*.json` exports
- Frontend consumes `data/*.json` directly

No auth, no user accounts, pure GitHub Actions automation.

## Security Posture Automation

The repo now has **full security automation**:

1. **Vulnerability Detection**: CodeQL (SAST), Trivy (container), tfsec/checkov (IaC), TruffleHog (secrets), pip-audit/safety (deps)
2. **Auto-Remediation**: Dependency autopatcher creates tested PRs
3. **Continuous Monitoring**: Daily security posture checks → GitHub Issues on critical findings
4. **Threat Intelligence**: 6-hourly feeds + fleet consensus correlation
5. **Active Scanning**: Daily web scans + weekly repo secret scans
6. **Alerting**: 15-min critical telemetry alerts → GitHub Issues; daily posture alerts → GitHub Issues

All results visible in GitHub Security tab, Actions artifacts, and the static frontend dashboard.