# Hybrid IDS + Incident Response Integration

This package integrates the useful parts of the uploaded **incident-response** project into the current **Hybrid IDS powered by AI** project.

## Important integration decision

The uploaded incident-response project is a separate React + FastAPI demo. Your Hybrid IDS project already uses:

- `app/` as the FastAPI backend
- `ui/` as the Streamlit dashboard

So we should **not** copy the whole React project into the Hybrid IDS project. That would create two frontends and two backends and make the graduation project confusing.

Instead, this integrated version keeps your original Hybrid IDS pipeline and adds Incident Response on top of its real IDS output.

## What was taken from the uploaded incident-response project

Useful ideas copied/adapted:

- incident records structure
- reports structure
- ticket log idea
- blocklist file idea
- isolated hosts file idea
- demo containment actions
- IR workflow: investigate → severity → actions → ticket/report

Not copied directly:

- `node_modules/`
- `dist/`
- `src/` React frontend
- `.env`
- separate `server.py` as a second backend

## Final flow

```text
PCAP or CICFlowMeter CSV
        ↓
Hybrid IDS Backend
        ↓
Packet Rules + Binary AI Models + Conditional Multiclass Model
        ↓
Incident Response Agent
        ↓
Severity, suspicious IPs, verification steps, recommended actions,
dry-run block commands, dry-run host-isolation commands, optional LLM report
```

## Files added/changed

### Added

- `app/ir_agent.py`
  - severity scoring
  - suspicious IP extraction
  - IR recommendations
  - dry-run mitigation commands
  - optional OpenRouter LLM report
  - demo IR state store based on `data/`

- `data/`
  - copied from the uploaded IR project:
    - `data/incidents/`
    - `data/reports/`
    - `data/tickets.jsonl`
    - `data/blocklist.txt`
    - `data/isolated_hosts.txt`

- `.env.example`
- `.gitignore`
- `requirements.txt`

### Changed

- `app/main.py`
  - analysis responses now include `incident_response`
  - supports CSV upload endpoints
  - new IR endpoints:
    - `GET /incident-response/status`
    - `POST /incident-response/execute-action`
    - `POST /incident-response/tickets`
    - `GET /incident-response/reports/{report_id}`
    - `POST /incident-response/llm`
  - compatibility aliases for the uploaded React IR routes:
    - `GET /api/status`
    - `POST /api/execute-action`
    - `POST /api/tickets`
    - `GET /api/reports/{report_id}`

- `app/schemas.py`
  - added `incident_response` field

- `ui/streamlit_app.py`
  - supports PCAP, PCAPNG, and CSV upload
  - added Incident Response tab
  - added optional LLM IR report generation

- `app/cicflowmeter_runner.py`
  - supports `CICFLOWMETER_BIN` environment variable

## Run backend

From the project folder:

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

## Run Streamlit UI

Open another terminal:

```powershell
.\.venv\Scripts\Activate.ps1
streamlit run ui/streamlit_app.py
```

Open:

```text
http://localhost:8501
```

## Test quickly with CSV

Use one of the files in `test_data/`. CSV mode skips CICFlowMeter and packet-rule PCAP processing, so it is easier for testing.

## Optional CICFlowMeter path

PowerShell:

```powershell
$env:CICFLOWMETER_BIN="D:\Downloads\CICFlowMeter-master\CICFlowMeter-master\build\install\CICFlowMeter\bin\CICFlowMeter.bat"
uvicorn app.main:app --reload
```

## Optional OpenRouter LLM report

PowerShell:

```powershell
$env:OPENROUTER_API_KEY="your_key_here"
$env:OPENROUTER_MODEL="openai/gpt-oss-20b:free"
uvicorn app.main:app --reload
```

## Safety note

All Incident Response actions are **demo/dry-run only**. The app updates local demo files such as `data/blocklist.txt` and `data/isolated_hosts.txt`. It does not really block IPs or isolate your laptop/network automatically.
