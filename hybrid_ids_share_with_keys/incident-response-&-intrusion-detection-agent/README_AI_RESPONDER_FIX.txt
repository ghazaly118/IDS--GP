SOAR AI Responder Real IDS Patch
================================

Use this patch on the Incident Response / SOAR project only.

It keeps the SOAR dashboard in Real IDS Handoff Mode:
- No quick-inject templates
- No local SOAR uploads
- Incidents must come from Hybrid IDS via POST /api/ids-ingest

It restores the important AI function:
- Run Autonomous AI Incident Responder
- Uses the selected real IDS incident
- Adds analyst context
- Calls POST /api/investigate-incident
- Writes markdown_report back into the same incident JSON
- Saves data/reports/<incident_id>.md

Files to replace:
- server.py
- src/App.tsx
- src/components/NetworkParser.tsx

After copying:
1) Stop the SOAR app with CTRL+C
2) Run: npm run dev
3) Send an incident from Hybrid IDS
4) Select the new incident in SOAR
5) Add analyst context if needed
6) Click Run Autonomous AI Incident Responder
7) Open the Forensic Report tab

GEMINI_API_KEY is optional. If it exists in .env, Gemini generates the report.
If it is missing, the backend creates a deterministic local fallback report for demo continuity.
