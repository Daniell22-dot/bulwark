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

Workflows:
- `.github/workflows/scheduled-scans.yml` - daily web + repo scans
- `.github/workflows/telemetry-rollup.yml` - hourly aggregation
- `.github/workflows/alert-check.yml` - every 15 min, creates GitHub Issues on critical events

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

## Data Flow

```
C# Agents (local)          Backend (cloud)           GitHub Actions              Frontend (static)
     │                         │                          │                        │
     ├─ POST /telemetry ────▶ │                          │                        │
     │                         ├─ SQLite store ──────────┤                        │
     │                         ├─ Sync to data/*.json ───┤                        │
     │                         │                          ├─ Hourly rollup ──────┤
     │                         │                          ├─ 15m alert check ───┤
     │                         │                          └─ Daily scans ───────┤
     │                         │                          │                        │
     │                         ◀──── GET /api/dashboard ┤                        │
     │                         │                          │                        ▼
     │                         │                          │                   Dashboard UI
```

## Environment Variables

| Var | Required | Default | Description |
|-----|----------|---------|-------------|
| `DATA_DIR` | No | `./data` | SQLite/JSON storage path |
| `PORT` | No | `8000` | HTTP port |
| `GITHUB_TOKEN` | Yes* | - | PAT for committing data/creating issues |
| `GITHUB_REPO` | Yes* | - | `owner/repo` for sync |
| `GITHUB_BRANCH` | No | `main` | Target branch |

*Required for GitHub sync/alerts. Omit if running standalone.

## Extending

Add routes in `app/routes/` and register in `app/main.py`. The pattern:
- Telemetry in = POST `/telemetry`
- Dashboard out = GET `/api/dashboard`
- Actions consume `data/*.json` exports
- Frontend consumes `/api/dashboard`

No auth, no user accounts, pure GitHub Actions automation.