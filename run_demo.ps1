# NetSight: Windows Native Launcher Script
# Usage: .\run_demo.ps1 [-Mode replay|live] [-Iface "\Device\NPF_{...}"]

param (
    [string]$Mode = "prompt",
    [string]$Iface = "",
    [int]$EnginePort = 9999,
    [int]$CollectorPort = 8000,
    [int]$DashboardPort = 5173
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Note: Live capture via Npcap requires Administrator privileges to open network adapters." -ForegroundColor Yellow
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  NetSight: High-Performance Network Telemetry & DPI      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Engine Binary First (needed for adapter listing)
$EngineBinary = Join-Path $ProjectRoot "engine\build\Release\netsight-engine.exe"
if (-not (Test-Path $EngineBinary)) {
    Write-Host "[!] Engine binary not found at $EngineBinary" -ForegroundColor Yellow
    Write-Host "[*] Building engine with CMake..." -ForegroundColor Gray
    Push-Location (Join-Path $ProjectRoot "engine")
    cmake -B build
    cmake --build build --config Release
    Pop-Location
}

if (-not (Test-Path $EngineBinary)) {
    Write-Error "Failed to locate or build netsight-engine.exe"
}
Write-Host "[+] C++ Engine binary: $EngineBinary" -ForegroundColor Green

# Select Mode if prompt requested
if ($Mode -eq "prompt" -or $Mode -eq "") {
    Write-Host ""
    Write-Host "Select Capture Mode:" -ForegroundColor Yellow
    Write-Host "  [1] Live Network Capture (REAL traffic from this laptop: X, Gmail, Gemini, etc.)" -ForegroundColor Green
    Write-Host "  [2] PCAP Replay Demo (Replay sample test_dpi.pcap benchmark)" -ForegroundColor White
    Write-Host ""
    $choice = Read-Host "Enter choice [1 or 2] (Default is 1: Live Capture)"
    if ($choice -eq "2") {
        $Mode = "replay"
    } else {
        $Mode = "live"
    }
}

# Interactive Npcap Adapter Picker with Recommended Driver Detection
if ($Mode -eq "live" -and $Iface -eq "") {
    Write-Host ""
    Write-Host "[*] Scanning Npcap Network Capture Drivers..." -ForegroundColor Cyan
    $rawOutput = & $EngineBinary --list-ifaces 2>&1
    $adapters = @()
    $recommendedAdapter = ""
    $currentAdapter = $null

    foreach ($line in $rawOutput) {
        $text = $line.ToString().Trim()
        if ($text -eq "" -or $text -match "^Available Network") {
            continue
        }
        if ($text -match "^\[(\d+)\]\s+(\\Device\\NPF_.+)$") {
            if ($null -ne $currentAdapter) { $adapters += $currentAdapter }
            $currentAdapter = [PSCustomObject]@{
                Index = [int]$matches[1]
                Name  = $matches[2].Trim()
                Desc  = "Network Adapter"
            }
        } elseif ($text -match "Default live adapter:" -or $text -match "\[LiveCapture\]") {
            if ($null -ne $currentAdapter) { $adapters += $currentAdapter; $currentAdapter = $null }
            if ($text -match "(\\Device\\NPF_\{[0-9A-Fa-f\-]+\})") {
                $recommendedAdapter = $matches[1].Trim()
            }
        } elseif ($text -match "^(\\Device\\NPF_\{[0-9A-Fa-f\-]+\})$") {
            if ($null -ne $currentAdapter) { $adapters += $currentAdapter; $currentAdapter = $null }
            $recommendedAdapter = $matches[1].Trim()
        } elseif ($null -ne $currentAdapter -and $currentAdapter.Desc -eq "Network Adapter") {
            $currentAdapter.Desc = $text
        }
    }
    if ($null -ne $currentAdapter) { $adapters += $currentAdapter }

    if ($adapters.Count -gt 0) {
        $recIndex = 0

        # 1. Match C++ routing table recommendation
        for ($i = 0; $i -lt $adapters.Count; $i++) {
            if ($adapters[$i].Name -eq $recommendedAdapter) {
                $recIndex = $adapters[$i].Index
                break
            }
        }

        # 2. Fallback: Prefer physical Wi-Fi / Ethernet adapter (never WAN Miniport or Wi-Fi Direct)
        if ($recIndex -eq 0) {
            foreach ($a in $adapters) {
                if ($a.Desc -match "Wi-Fi|WiFi|Wireless|802\.11|Realtek|Intel|Ethernet" -and
                    $a.Desc -notmatch "WAN Miniport|Wi-Fi Direct|Virtual|Hyper-V|Loopback") {
                    $recIndex = $a.Index
                    break
                }
            }
        }
        if ($recIndex -eq 0) { $recIndex = 1 }

        Write-Host ""
        Write-Host "Available Npcap Capture Drivers:" -ForegroundColor Yellow
        foreach ($a in $adapters) {
            $isVirtual = $a.Desc -match "WAN Miniport|Wi-Fi Direct|Hyper-V|Loopback"
            if ($a.Index -eq $recIndex) {
                Write-Host ("  [{0}] {1} - {2}  <-- [RECOMMENDED: Active Internet Adapter]" -f $a.Index, $a.Desc, $a.Name) -ForegroundColor Green
            } elseif ($isVirtual) {
                Write-Host ("  [{0}] {1} - {2}  (Virtual/Idle)" -f $a.Index, $a.Desc, $a.Name) -ForegroundColor DarkGray
            } else {
                Write-Host ("  [{0}] {1} - {2}" -f $a.Index, $a.Desc, $a.Name) -ForegroundColor White
            }
        }
        Write-Host ""
        $pick = Read-Host "Select adapter [1-$($adapters.Count)] (Press Enter for Recommended [$recIndex])"
        if ([string]::IsNullOrWhiteSpace($pick)) {
            $selectedObj = $adapters | Where-Object { $_.Index -eq $recIndex } | Select-Object -First 1
            $Iface = $selectedObj.Name
        } elseif ($pick -match "^\d+$") {
            $idx = [int]$pick
            $selectedObj = $adapters | Where-Object { $_.Index -eq $idx } | Select-Object -First 1
            if ($null -ne $selectedObj) {
                $Iface = $selectedObj.Name
            } else {
                $selectedObj = $adapters | Where-Object { $_.Index -eq $recIndex } | Select-Object -First 1
                $Iface = $selectedObj.Name
            }
        } else {
            $Iface = $pick.Trim()
        }
    }
}

# 2. Check Dashboard Dependencies and Build
$DashboardDir = Join-Path $ProjectRoot "dashboard"
$DashboardDist = Join-Path $DashboardDir "dist"
$NodeModules = Join-Path $DashboardDir "node_modules"
$NpmCmd = (Get-Command npm.cmd -ErrorAction SilentlyContinue).Source
if (-not $NpmCmd) { $NpmCmd = "npm" }

if (-not (Test-Path $DashboardDist)) {
    if (-not (Test-Path $NodeModules)) {
        Write-Host "[*] Installing dashboard dependencies (npm install)..." -ForegroundColor Gray
        Push-Location $DashboardDir
        & $NpmCmd install
        Pop-Location
    }
    Write-Host "[*] Building dashboard frontend..." -ForegroundColor Gray
    Push-Location $DashboardDir
    & $NpmCmd run build
    Pop-Location
}
if (Test-Path $DashboardDist) {
    Write-Host "[+] Dashboard production build ready." -ForegroundColor Green
}

# 3. Start C++ Engine
$EngineArgs = @("--port", $EnginePort)
if ($Mode -eq "replay") {
    $TestPcap = Join-Path $ProjectRoot "test_data\test_dpi.pcap"
    $EngineArgs += @("--replay", $TestPcap, "--speed", "10", "--loop")
    Write-Host "[*] Starting Engine in REPLAY mode with $TestPcap on port $EnginePort..." -ForegroundColor Cyan
} else {
    if ($Iface -ne "") {
        $EngineArgs += @("--iface", $Iface)
        Write-Host "[*] Starting Engine in LIVE capture mode on interface '$Iface' on port $EnginePort..." -ForegroundColor Cyan
    } else {
        $EngineArgs += @("--iface")
        Write-Host "[*] Starting Engine in LIVE capture mode (auto-selecting default Npcap interface)..." -ForegroundColor Cyan
    }
}

$EngineProc = Start-Process -FilePath $EngineBinary -ArgumentList $EngineArgs -PassThru -NoNewWindow
Start-Sleep -Seconds 1

# 4. Start Python Collector
Write-Host "[*] Starting Python Collector on http://127.0.0.1:$CollectorPort..." -ForegroundColor Cyan
$env:ENGINE_PORT = $EnginePort
$env:COLLECTOR_PORT = $CollectorPort
$CollectorProc = Start-Process -FilePath "python" -ArgumentList "-m", "uvicorn", "collector.main:app", "--host", "127.0.0.1", "--port", "$CollectorPort" -PassThru -NoNewWindow
Start-Sleep -Seconds 2

# 5. Start Dashboard Server
$ViteBin = Join-Path $DashboardDir "node_modules\.bin\vite.cmd"
$DashboardUrl = "http://localhost:$DashboardPort"

if (Test-Path $ViteBin) {
    Write-Host "[*] Starting Dashboard on http://localhost:$DashboardPort (via Vite preview)..." -ForegroundColor Cyan
    Push-Location $DashboardDir
    $DashboardProc = Start-Process -FilePath $NpmCmd -ArgumentList "run", "preview", "--", "--port", "$DashboardPort", "--host", "127.0.0.1" -PassThru -NoNewWindow
    Pop-Location
} elseif (Test-Path $DashboardDist) {
    Write-Host "[*] Vite binary not detected; serving Dashboard directly through Collector on http://127.0.0.1:$CollectorPort..." -ForegroundColor Green
    $DashboardUrl = "http://127.0.0.1:$CollectorPort"
} else {
    Write-Host "[!] Dashboard dist not found. Please run 'npm install && npm run build' in dashboard." -ForegroundColor Yellow
}

Start-Sleep -Seconds 2
try {
    Start-Process $DashboardUrl -ErrorAction SilentlyContinue
} catch {
}

Write-Host ""
Write-Host "[SUCCESS] NetSight is running!" -ForegroundColor Green
Write-Host "  - Dashboard: $DashboardUrl" -ForegroundColor White
Write-Host "  - REST API:  http://127.0.0.1:$CollectorPort/api/summary" -ForegroundColor White
Write-Host "  - WS Stream: ws://127.0.0.1:$CollectorPort/ws/live" -ForegroundColor White
Write-Host "  - Engine:    port $EnginePort" -ForegroundColor White
Write-Host ""
Write-Host "Press Ctrl+C or Enter to stop all services..." -ForegroundColor Yellow

try {
    [Console]::ReadLine()
} finally {
    Write-Host "[*] Shutting down NetSight services..." -ForegroundColor Gray
    if ($EngineProc -and -not $EngineProc.HasExited) { Stop-Process -Id $EngineProc.Id -Force -ErrorAction SilentlyContinue }
    if ($CollectorProc -and -not $CollectorProc.HasExited) { Stop-Process -Id $CollectorProc.Id -Force -ErrorAction SilentlyContinue }
    if ($DashboardProc -and -not $DashboardProc.HasExited) { Stop-Process -Id $DashboardProc.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "[+] All processes terminated cleanly." -ForegroundColor Green
}
