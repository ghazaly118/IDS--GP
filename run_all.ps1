# ============================================================
# HYBRID IDS + ZERO-DAY + SOAR — ONE-CLICK LAUNCHER
# Run this script from PowerShell:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
#   .\run_all.ps1
# ============================================================

$BASE = "C:\Users\amoha\OneDrive\Desktop\gp\gp\hybrid_ids_share_with_keys"
$SOAR = "$BASE\incident-response-&-intrusion-detection-agent"
$CFM  = "C:\Users\amoha\OneDrive\Desktop\gp\gp\cicflowmeter_custom\bin\CICFlowMeter.bat"
$PY   = "$BASE\.venv\Scripts\python.exe"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  HYBRID IDS + SOAR — Starting All Services" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Terminal 1 — IDS Backend (port 8000)
Write-Host "[1/3] Starting Hybrid IDS Backend on http://127.0.0.1:8000 ..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", `
    "`$env:CICFLOWMETER_BIN='$CFM'; cd '$BASE'; & '$PY' -m uvicorn app.main:app --reload --port 8000"

Start-Sleep -Seconds 2

# Terminal 2 — Streamlit Dashboard (port 8501)
Write-Host "[2/3] Starting Streamlit Dashboard on http://localhost:8501 ..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", `
    "cd '$BASE'; & '$PY' -m streamlit run ui/streamlit_app.py"

Start-Sleep -Seconds 2

# Terminal 3 — SOAR Backend + React UI (ports 8001 + 5173)
Write-Host "[3/3] Starting SOAR Dashboard on http://localhost:5173 ..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", `
    "cd '$SOAR'; cmd /c 'npm run dev'"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  All services launched in separate windows!" -ForegroundColor Green
Write-Host ""
Write-Host "  Hybrid IDS Dashboard : http://localhost:8501" -ForegroundColor Green
Write-Host "  SOAR Dashboard       : http://localhost:5173" -ForegroundColor Green
Write-Host "  IDS Backend API      : http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "  SOAR Backend API     : http://127.0.0.1:8001" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Wait ~15 seconds for all services to fully start." -ForegroundColor DarkCyan
Write-Host "Then open your browser to the URLs above." -ForegroundColor DarkCyan
Write-Host ""
