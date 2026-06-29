# Hybrid IDS + Zero-Day Detection + SOAR Incident Response

A full-stack network intrusion detection system combining:
- **Binary classification** (BENIGN vs ATTACK) using XGBoost + LSTM ensemble
- **Multiclass attack classification** (14 attack types)
- **Zero-day detection** via autoencoder anomaly scoring
- **SOAR Incident Response** powered by Gemini AI — autonomous forensics, containment plans, and ticketing

---

## Architecture

```
PCAP / CSV Upload
      │
      ▼
CICFlowMeter (flow extraction)
      │
      ▼
Binary Model (XGBoost + LSTM)
      │
      ├── BENIGN ──► Zero-Day Autoencoder (anomaly scan) ──► Safe ✅
      │
      └── ATTACK ──► Multiclass Model (attack type)
                          │
                          ▼
                    SOAR Handoff ──► Gemini AI Incident Responder
                                          │
                                          ▼
                                   Forensic Report + Containment Plan
```

---

## Prerequisites

Install these before setup:

| Tool | Version | Download |
|------|---------|---------|
| Python | 3.12 (not 3.13+) | https://www.python.org/downloads/ |
| Node.js + npm | 18+ | https://nodejs.org/ |
| Java JDK | 11+ | https://adoptium.net/ |
| CICFlowMeter (custom build) | — | See note below |

> **Python 3.12 is required.** TensorFlow does not support Python 3.13/3.14 yet.

> **CICFlowMeter** is only needed if you upload raw PCAP/PCAPNG files.  
> If you upload a pre-generated CICFlowMeter CSV, you can skip it.

> **ML Models** are not included in this repo (too large for GitHub).  
> Place them under `models/` as described in the folder structure below.

---

## Folder Structure

```
hybrid_ids_share_with_keys/
├── app/                    # FastAPI backend + ML inference
├── ui/                     # Streamlit dashboard
├── models/                 # ⚠️ NOT in repo — add your model files here
│   ├── cicids_lstm_out_v2/
│   ├── cicids_xgb_flow_v1/
│   ├── multiclass_stage2/
│   └── zero_day_autoencoder/
├── incident-response-&-intrusion-detection-agent/
│   ├── src/                # React SOAR frontend
│   ├── server.py           # FastAPI SOAR backend
│   ├── .env.example        # Copy to .env and add your API key
│   └── package.json
├── requirements.txt
└── .gitignore
```

---

## Setup & Run

### Step 1 — Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd hybrid_ids_share_with_keys
```

### Step 2 — Add your ML models

Place your trained model folders inside `models/`:
```
models/cicids_lstm_out_v2/
models/cicids_xgb_flow_v1/
models/multiclass_stage2/
models/zero_day_autoencoder/
```

### Step 3 — Create Python virtual environment (Python 3.12)

**Windows PowerShell:**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**macOS / Linux:**
```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 4 — Configure SOAR environment

```bash
cd incident-response-&-intrusion-detection-agent
cp .env.example .env
```

Edit `.env` and add your Gemini API key:
```
GEMINI_API_KEY=your_key_here
APP_URL=http://localhost:5173
```

Get a free Gemini API key at: https://aistudio.google.com/apikey

### Step 5 — Install React dependencies

```bash
cd incident-response-&-intrusion-detection-agent
npm install
```

---

## Running the App

Open **3 separate terminals** from the project root:

### Terminal 1 — Hybrid IDS Backend (port 8000)

```powershell
# Windows
cd hybrid_ids_share_with_keys
$env:CICFLOWMETER_BIN="C:\path\to\cicflowmeter_custom\bin\CICFlowMeter.bat"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

```bash
# macOS/Linux
cd hybrid_ids_share_with_keys
export CICFLOWMETER_BIN="/path/to/cicflowmeter_custom/bin/CICFlowMeter"
.venv/bin/python -m uvicorn app.main:app --reload --port 8000
```

### Terminal 2 — Streamlit Dashboard (port 8501)

```powershell
# Windows
.\.venv\Scripts\python.exe -m streamlit run ui/streamlit_app.py
```

```bash
# macOS/Linux
.venv/bin/python -m streamlit run ui/streamlit_app.py
```

### Terminal 3 — SOAR Backend + React UI (ports 8001 + 5173)

```bash
cd incident-response-&-intrusion-detection-agent
npm run dev
```

---

## One-Click Scripts (Windows only)

```powershell
# Start everything
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\run_all.ps1

# Stop everything
.\stop_all.ps1
```

---

## Open in Browser

| Interface | URL |
|-----------|-----|
| Hybrid IDS Dashboard | http://localhost:8501 |
| SOAR Incident Response | http://localhost:5173 |
| IDS API (FastAPI docs) | http://127.0.0.1:8000/docs |
| SOAR API (FastAPI docs) | http://127.0.0.1:8001/docs |

---

## Demo Flow

1. Open **http://localhost:8501**
2. Upload a **PCAP / PCAPNG** or **CICFlowMeter CSV** file
3. Click **Analyze**
4. Pipeline runs automatically:
   - Binary model → ATTACK or BENIGN
   - If **ATTACK**: Multiclass + Zero-Day models run → results shown
   - If **BENIGN**: Zero-Day autoencoder runs for anomaly scan
5. If result is **ATTACK** → click **"Send to SOAR Incident Response"**
6. Open **http://localhost:5173**
7. Select the incident → add analyst context (optional)
8. Click **"Run Autonomous AI Incident Responder"**
9. Get: AI forensic report, investigation plan, containment recommendations

---

## Common Errors

**`tensorflow not found` / No matching distribution**
```
Use Python 3.12. Python 3.13+ is not supported by tensorflow yet.
py -3.12 -m venv .venv
```

**`running scripts is disabled on this system`**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

**`Port 8000 already in use`**
```powershell
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

**SOAR report not generated**
- Check `.env` exists with a valid `GEMINI_API_KEY`
- Make sure SOAR backend is running on port 8001
- Select a real IDS incident (not empty)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| ML Models | XGBoost, LSTM (TensorFlow/Keras), Autoencoder |
| IDS Backend | FastAPI + Uvicorn |
| IDS Frontend | Streamlit |
| SOAR Backend | FastAPI + Uvicorn |
| SOAR Frontend | React + Vite + TypeScript + TailwindCSS |
| AI Engine | Google Gemini API |
| Flow Extraction | CICFlowMeter |

---

## License

For academic/research use. See `LICENSE` for details.
