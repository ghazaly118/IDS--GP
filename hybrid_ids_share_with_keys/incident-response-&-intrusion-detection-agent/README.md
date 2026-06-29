# Incident Response & Intrusion Detection Agent

Autonomous AI-powered SecOps dashboard with:
- **React 19 + TypeScript + Vite + Tailwind CSS** frontend
- **Python FastAPI + Uvicorn** backend
- **Google Gemini AI** for forensic investigation (with full mock fallback)

---

## Architecture

```
┌─────────────────────┐      /api/* proxy      ┌──────────────────────────┐
│  Vite Dev Server    │ ──────────────────────> │  FastAPI (Uvicorn)       │
│  localhost:5173     │                         │  localhost:8000          │
│  React + TypeScript │                         │  server.py               │
└─────────────────────┘                         └──────────────────────────┘
                                                           │
                                                    data/incidents/
                                                    data/reports/
                                                    data/tickets.jsonl
                                                    data/blocklist.txt
                                                    data/isolated_hosts.txt
```

---

## Quick Start

### 1. Install Node dependencies
```bash
npm install
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure environment
Edit `.env` and add your Gemini API key:
```
GEMINI_API_KEY=your_key_here
```
> Without a key the server runs in high-fidelity mock simulation mode — all features still work.

### 4. Run both servers with one command
```bash
npm run dev
```
This starts **Uvicorn** (FastAPI on port 8000) and **Vite** (React on port 5173) concurrently.  
Open **http://localhost:5173** in your browser.

### Alternative: Run servers separately
```bash
# Terminal 1 — FastAPI backend
npm run dev:api
# or directly: uvicorn server:app --reload --port 8000

# Terminal 2 — Vite frontend
npm run dev:ui
```

---

## API Endpoints (FastAPI)

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/status` | Full IR system state (incidents, endpoints, blocklist) |
| POST | `/api/upload-flow` | Heuristic ML IDS classifier from CSV/PCAP flow data |
| POST | `/api/investigate` | Gemini AI forensic investigation + MITRE + CVSS + report |
| POST | `/api/execute-action` | Containment: `isolate_host`, `block_ip`, `kill_process` |
| POST | `/api/tickets` | Create incident escalation ticket |
| GET | `/api/reports/{id}` | Raw Markdown forensic report |

Interactive API docs available at **http://localhost:8000/docs** (Swagger UI).

---

## Project Structure

```
├── server.py              # FastAPI backend (replaces server.ts)
├── requirements.txt       # Python dependencies
├── .env                   # Environment variables (GEMINI_API_KEY)
├── package.json           # npm scripts + frontend deps
├── vite.config.ts         # Vite config with /api proxy to :8000
├── src/
│   ├── App.tsx            # Main dashboard layout
│   ├── types.ts           # TypeScript interfaces
│   ├── main.tsx           # React entry point
│   ├── index.css          # Global styles
│   └── components/
│       ├── NetworkParser.tsx      # Flow upload + ML IDS classifier
│       ├── InvestigationPanel.tsx # Forensic findings + MITRE + report
│       └── EndpointConsole.tsx    # Live endpoint firewall/process console
└── data/                  # Auto-created on first run
    ├── incidents/         # Per-incident JSON files
    ├── reports/           # Per-incident Markdown reports
    ├── tickets.jsonl      # Append-only ticket log
    ├── blocklist.txt      # Blocked IPs
    └── isolated_hosts.txt # Isolated host names
```
