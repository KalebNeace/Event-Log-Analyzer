# =============================================================
# collect.ps1 - Log Analyzer Entry Point
# Collects Windows Event Logs and pipes data to Python analyzer
# =============================================================

param(
    [string]$ConfigPath = "$PSScriptRoot\config.json",
    [switch]$OpenReport
)

# ── Load Config ───────────────────────────────────────────────
if (-not (Test-Path $ConfigPath)) {
    Write-Error "Config file not found at: $ConfigPath"
    exit 1
}

$config = Get-Content $ConfigPath | ConvertFrom-Json

# Build dated subfolder: output\2026-03-27_14-30-00
$dateStamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outputDir = Join-Path $PSScriptRoot (Join-Path $config.output_dir $dateStamp)

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

# ── Helper: Write colored status messages ─────────────────────
function Write-Status {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "[*] $Message" -ForegroundColor $Color
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

# ── Collect Event Logs ────────────────────────────────────────
Write-Host ""
Write-Host "=================================================" -ForegroundColor DarkCyan
Write-Host "   Windows Log Analyzer - Collection Phase" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor DarkCyan
Write-Host ""

$allEvents = @()
$hoursBack = $config.hours_back
$startTime = (Get-Date).AddHours(-$hoursBack)

foreach ($channel in $config.log_channels) {
    Write-Status "Collecting from channel: $channel"

    try {
        # Security log requires elevation - warn gracefully
        if ($channel -eq "Security") {
            $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
            if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                Write-Warn "Skipping Security log - requires Administrator privileges."
                continue
            }
        }

        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $channel
            StartTime = $startTime
        } -ErrorAction Stop | Select-Object -First $config.max_events_per_channel

        foreach ($e in $events) {
            $allEvents += [PSCustomObject]@{
                TimeCreated  = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Channel      = $channel
                Level        = $e.LevelDisplayName
                EventId      = $e.Id
                ProviderName = $e.ProviderName
                Message      = ($e.Message -replace "`r`n|`n|`r", " ") -replace '"', "'"
            }
        }

        Write-Success "Collected $($events.Count) events from $channel"
    }
    catch [System.Exception] {
        if ($_.Exception.Message -like "*No events*") {
            Write-Warn "No events found in '$channel' for the past $hoursBack hours."
        } else {
            Write-Warn "Could not read '$channel': $($_.Exception.Message)"
        }
    }
}

if ($allEvents.Count -eq 0) {
    Write-Host ""
    Write-Warn "No events were collected. Check your config.json channels and hours_back setting."
    exit 1
}

Write-Host ""
Write-Status "Total events collected: $($allEvents.Count)"

# ── Export raw events to JSON for Python ─────────────────────
$rawPath = Join-Path $outputDir "raw_events.json"
$allEvents | ConvertTo-Json -Depth 5 | Set-Content -Path $rawPath -Encoding UTF8
Write-Success "Raw events saved to: $rawPath"

# ── Call Python Analyzer ──────────────────────────────────────
Write-Host ""
Write-Host "=================================================" -ForegroundColor DarkCyan
Write-Host "   Invoking Python Analysis Engine" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor DarkCyan
Write-Host ""

$pythonScripts = @("python", "python3", "py")
$pythonCmd = $null

foreach ($cmd in $pythonScripts) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        $pythonCmd = $cmd
        break
    }
}

if (-not $pythonCmd) {
    Write-Error "Python not found. Please install Python 3 and ensure it is in your PATH."
    exit 1
}

$analyzeScript = Join-Path $PSScriptRoot "analyze.py"
& $pythonCmd $analyzeScript --input $rawPath --output $outputDir --config $ConfigPath

if ($LASTEXITCODE -ne 0) {
    Write-Error "Python analysis failed with exit code $LASTEXITCODE"
    exit 1
}

# ── Generate HTML Report via Python ──────────────────────────
Write-Host ""
Write-Host "=================================================" -ForegroundColor DarkCyan
Write-Host "   Generating HTML Report" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor DarkCyan
Write-Host ""

$reportScript = Join-Path $PSScriptRoot "report.py"
& $pythonCmd $reportScript --output $outputDir

if ($LASTEXITCODE -ne 0) {
    Write-Error "Report generation failed."
    exit 1
}

# ── Final Summary ─────────────────────────────────────────────
Write-Host ""
Write-Host "=================================================" -ForegroundColor Green
Write-Host "   Analysis Complete!" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
Write-Host ""
Write-Success "CSV Report  : $(Join-Path $outputDir 'summary.csv')"
Write-Success "JSON Results: $(Join-Path $outputDir 'results.json')"
Write-Success "HTML Report : $(Join-Path $outputDir 'report.html')"
Write-Host ""

# Auto-open HTML report
$htmlReport = Join-Path $outputDir "report.html"
if ($config.auto_open_report -or $OpenReport) {
    if (Test-Path $htmlReport) {
        Write-Status "Opening report in browser..."
        Start-Process $htmlReport
    }
}