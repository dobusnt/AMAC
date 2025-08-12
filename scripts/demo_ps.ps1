<# 
Runs the full local demo pipeline in PowerShell:

1) Start the mock API in a separate PowerShell window (if not already running).
2) Map → Check → Probe → Analyze → Report against the local OpenAPI.

Usage:
  pwsh -File scripts/demo_ps.ps1
#>

param(
  [string]$HostAddr = "127.0.0.1",
  [int]$Port = 8008,
  [string]$BearerToken = "demo"
)

$ErrorActionPreference = "Stop"

# Move to repo root
Set-Location -Path (Split-Path -Parent $MyInvocation.MyCommand.Path) | Out-Null
Set-Location ..

# Optional: activate venv if present
$venv = ".\.venv\Scripts\Activate.ps1"
if (Test-Path $venv) {
  . $venv
}

# Ensure package is installed (editable)
python -m pip install -U pip | Out-Null
pip install -e . | Out-Null

$env:DEMO_BEARER_TOKEN = $BearerToken

# Spawn mock API in a new window if not already listening
$mockUrl = "http://$HostAddr`:$Port/status"
try {
  Invoke-WebRequest -Uri $mockUrl -Method Head -TimeoutSec 1 | Out-Null
  Write-Host "Mock API appears to be running at $mockUrl"
} catch {
  Write-Host "Starting mock API in a new PowerShell window..."
  $mockCmd = "pwsh -NoExit -Command `"`$env:MOCK_HOST='$HostAddr'; `$env:MOCK_PORT='$Port'; `$env:DEMO_BEARER_TOKEN='$BearerToken'; python scripts/mock_api.py`""
  Start-Process powershell -ArgumentList "-NoExit","-Command",$mockCmd | Out-Null
  Start-Sleep -Seconds 1
}

# Paths
$outDir = "out"
$runDir = Join-Path $outDir "run_demo"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
if (Test-Path $runDir) { Remove-Item -Recurse -Force $runDir }

Write-Host "[1/5] Mapping endpoints..."
python -m amac.cli map `
  --openapi examples/openapi_local.json `
  --scope   examples/scope_local.yml `
  --out     $outDir/local_endpoints.json

Write-Host "`n[2/5] Validating configs and endpoints..."
python -m amac.cli check `
  --endpoints $outDir/local_endpoints.json `
  --scope     examples/scope_local.yml `
  --auth      examples/auth_demo.yml

Write-Host "`n[3/5] Probing (no-auth vs bearer_demo)..."
python -m amac.cli probe `
  --endpoints $outDir/local_endpoints.json `
  --scope     examples/scope_local.yml `
  --auth      examples/auth_demo.yml `
  --out-dir   $runDir

Write-Host "`n[4/5] Analyzing probe run..."
python -m amac.cli analyze --run-dir $runDir

Write-Host "`n[5/5] Building HTML report..."
python -m amac.cli report --run-dir $runDir

Write-Host "`n✅ Done."
Write-Host "  Endpoints: $outDir\local_endpoints.json"
Write-Host "  Probe run: $runDir"
Write-Host "  Findings:  $runDir\findings.json and $runDir\findings.md"
Write-Host "  Report:    $runDir\report.html"
