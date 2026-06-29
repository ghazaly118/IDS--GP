# ============================================================
# HYBRID IDS + ZERO-DAY + SOAR -- ONE-CLICK SHUTDOWN
# Run: .\stop_all.ps1
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "  HYBRID IDS + SOAR -- Shutting Down All Services" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""

# Kill process by port number
function Kill-Port([int]$Port, [string]$Label) {
    $lines = netstat -ano | Select-String ":$Port "
    $killed = $false
    foreach ($line in $lines) {
        $parts = ($line -split '\s+') | Where-Object { $_ -ne '' }
        $pid2 = $parts[-1]
        if ($pid2 -match '^\d+$' -and [int]$pid2 -gt 0) {
            try {
                Stop-Process -Id ([int]$pid2) -Force -ErrorAction SilentlyContinue
                $killed = $true
            } catch {}
        }
    }
    if ($killed) {
        Write-Host "  [STOPPED] $Label (port $Port)" -ForegroundColor Green
    } else {
        Write-Host "  [SKIPPED] $Label (port $Port) -- not running" -ForegroundColor DarkGray
    }
}

Kill-Port 8000 "Hybrid IDS Backend  "
Kill-Port 8501 "Streamlit Dashboard "
Kill-Port 8001 "SOAR API Backend    "
Kill-Port 5173 "SOAR React UI (Vite)"

Write-Host ""
Write-Host "  Cleaning up remaining uvicorn / streamlit / node processes..." -ForegroundColor Yellow

$procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -ne $null }

foreach ($p in $procs) {
    $cmd = $p.CommandLine
    $isTarget = ($cmd -like "*uvicorn*") -or
                ($cmd -like "*streamlit*") -or
                ($cmd -like "*vite*") -or
                ($cmd -like "*concurrently*")
    if ($isTarget) {
        try {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Host "  [KILLED] PID $($p.ProcessId) -- $($p.Name)" -ForegroundColor DarkYellow
        } catch {}
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  All services stopped." -ForegroundColor Green
Write-Host "  Run .\run_all.ps1 to start again." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
