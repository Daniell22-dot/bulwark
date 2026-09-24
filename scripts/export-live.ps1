# Export the fleet console's /api/live feed into the site's bundled snapshot.
# Run this on the machine running Sentinel.Console, then commit data/live.json.
#
#   powershell -ExecutionPolicy Bypass -File scripts\export-live.ps1
#
param(
    [string]$Console = "http://localhost:5000",
    [string]$Out     = (Join-Path $PSScriptRoot "..\data\live.json")
)

$ErrorActionPreference = "Stop"
$live = Invoke-RestMethod -Uri "$Console/api/live" -TimeoutSec 15

$payload = [ordered]@{
    generatedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    updatedUtc   = $live.updatedUtc
    events       = $live.events
}

$Out = [System.IO.Path]::GetFullPath($Out)
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
$json = $payload | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($Out, $json, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "wrote $Out ($(@($live.events).Count) events)"
