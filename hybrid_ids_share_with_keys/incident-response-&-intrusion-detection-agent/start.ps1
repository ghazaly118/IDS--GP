# start.ps1 — Starts both the FastAPI backend and React frontend
# Run this from the project folder: .\start.ps1

node node_modules/concurrently/dist/bin/concurrently.js `
  --kill-others `
  --names "API,UI" `
  --prefix-colors "cyan,magenta" `
  "uvicorn server:app --reload --port 8000" `
  "node node_modules/vite/bin/vite.js"
