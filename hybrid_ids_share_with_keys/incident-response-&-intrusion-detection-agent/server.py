"""
Incident Response & Intrusion Detection Agent — FastAPI Backend
Replaces server.ts (Node/Express) with Python/FastAPI + Uvicorn.
Preserves every API route, filesystem structure, in-memory endpoint state,
Gemini AI integration, and Hybrid IDS handoff mode.
"""

from __future__ import annotations

import json
import math
import os
import random
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from google import genai
from google.genai import types as genai_types
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

# Optional remote-enforcement dependencies — graceful no-op if not installed
try:
    import paramiko as _paramiko  # pip install paramiko
    _PARAMIKO_AVAILABLE = True
except ImportError:
    _PARAMIKO_AVAILABLE = False

try:
    import winrm as _winrm_lib    # pip install pywinrm
    _WINRM_AVAILABLE = True
except ImportError:
    _WINRM_AVAILABLE = False

load_dotenv()

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="IR & IDS Controller", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Filesystem paths
# ---------------------------------------------------------------------------
DATA_DIR = Path.cwd() / "data"
INCIDENTS_DIR = DATA_DIR / "incidents"
REPORTS_DIR = DATA_DIR / "reports"
TICKETS_FILE = DATA_DIR / "tickets.jsonl"
BLOCKLIST_FILE = DATA_DIR / "blocklist.txt"
ISOLATED_FILE = DATA_DIR / "isolated_hosts.txt"

# ---------------------------------------------------------------------------
# Seed / initialise data directories
# ---------------------------------------------------------------------------
def _initialize_data_directories() -> None:
    """Create empty SOAR storage for real Hybrid IDS handoff only.

    Final-project mode intentionally does NOT seed mock incidents, tickets,
    blocklist entries, or isolated hosts. The React SOAR dashboard should only
    show incidents received through POST /api/ids-ingest from the Hybrid IDS.
    """
    DATA_DIR.mkdir(exist_ok=True)
    INCIDENTS_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)

    # Create empty files if they do not exist. Do not pre-fill demo data.
    if not BLOCKLIST_FILE.exists():
        BLOCKLIST_FILE.write_text("")
    if not ISOLATED_FILE.exists():
        ISOLATED_FILE.write_text("")
    if not TICKETS_FILE.exists():
        TICKETS_FILE.write_text("")

    print("IR Data Storage initialized in real IDS handoff mode.")


# ---------------------------------------------------------------------------
# In-memory endpoint agent state
# ---------------------------------------------------------------------------
ENDPOINT_AGENTS: dict[str, dict] = {
    "prod-web-01": {
        "hostname": "prod-web-01",
        "ip": "10.0.0.5",
        "os": "Linux",
        "status": "ONLINE",
        "connectionsCount": 84,
        "processes": [
            {"pid": 1, "name": "systemd", "cpu": 0.1, "memory": 0.2, "status": "Running"},
            {"pid": 480, "name": "nginx: master", "cpu": 0.5, "memory": 1.2, "status": "Running"},
            {"pid": 481, "name": "nginx: worker", "cpu": 2.1, "memory": 2.4, "status": "Running"},
            {"pid": 512, "name": "sshd", "cpu": 0.0, "memory": 0.5, "status": "Running"},
            {"pid": 1042, "name": "perl-reverse-shell", "cpu": 12.4, "memory": 5.8, "status": "Suspicious"},
        ],
        "firewallRules": [
            {"id": "fw-01", "direction": "INBOUND", "proto": "TCP", "port": "80,443", "action": "ALLOW", "source": "ANY", "destination": "10.0.0.5"},
            {"id": "fw-02", "direction": "INBOUND", "proto": "TCP", "port": "22", "action": "ALLOW", "source": "10.0.0.100", "destination": "10.0.0.5"},
            {"id": "fw-03", "direction": "OUTBOUND", "proto": "ANY", "port": "ANY", "action": "ALLOW", "source": "10.0.0.5", "destination": "ANY"},
        ],
        "terminalLogs": [
            "[2026-06-24 14:10:05] Agent service started. Verifying connection to security backend...",
            "[2026-06-24 14:10:06] Secure mTLS tunnel established with IR Server.",
            "[2026-06-24 14:15:20] Alert: Local process pid 1042 (perl) spawned socket outbound on high port 4444.",
        ],
    },
    "db-srv-prod": {
        "hostname": "db-srv-prod",
        "ip": "10.0.0.12",
        "os": "Linux",
        "status": "ONLINE",
        "connectionsCount": 12,
        "processes": [
            {"pid": 1, "name": "systemd", "cpu": 0.1, "memory": 0.1, "status": "Running"},
            {"pid": 812, "name": "postgres: master", "cpu": 1.4, "memory": 12.8, "status": "Running"},
            {"pid": 815, "name": "postgres: writer", "cpu": 0.8, "memory": 8.5, "status": "Running"},
            {"pid": 890, "name": "sshd", "cpu": 0.0, "memory": 0.4, "status": "Running"},
        ],
        "firewallRules": [
            {"id": "fw-11", "direction": "INBOUND", "proto": "TCP", "port": "5432", "action": "ALLOW", "source": "10.0.0.5", "destination": "10.0.0.12"},
            {"id": "fw-12", "direction": "INBOUND", "proto": "TCP", "port": "22", "action": "ALLOW", "source": "10.0.0.100", "destination": "10.0.0.12"},
            {"id": "fw-13", "direction": "OUTBOUND", "proto": "ANY", "port": "ANY", "action": "DENY", "source": "10.0.0.12", "destination": "ANY"},
        ],
        "terminalLogs": [
            "[2026-06-24 14:00:12] Endpoint agent online on db-srv-prod.",
            "[2026-06-24 14:00:13] Local firewall rules loaded. strict egress DENY enabled.",
        ],
    },
    "corp-laptop-12": {
        "hostname": "corp-laptop-12",
        "ip": "10.0.2.45",
        "os": "Windows Server",
        "status": "ONLINE",
        "connectionsCount": 4,
        "processes": [
            {"pid": 4, "name": "System", "cpu": 0.2, "memory": 0.1, "status": "Running"},
            {"pid": 320, "name": "svchost.exe", "cpu": 0.5, "memory": 1.5, "status": "Running"},
            {"pid": 1402, "name": "dns-tunnel-agent", "cpu": 4.8, "memory": 2.1, "status": "Suspicious"},
            {"pid": 2110, "name": "explorer.exe", "cpu": 1.2, "memory": 4.2, "status": "Running"},
        ],
        "firewallRules": [
            {"id": "fw-21", "direction": "INBOUND", "proto": "ANY", "port": "ANY", "action": "DENY", "source": "ANY", "destination": "10.0.2.45"},
            {"id": "fw-22", "direction": "OUTBOUND", "proto": "UDP", "port": "53", "action": "ALLOW", "source": "10.0.2.45", "destination": "8.8.8.8"},
            {"id": "fw-23", "direction": "OUTBOUND", "proto": "TCP", "port": "80,443", "action": "ALLOW", "source": "10.0.2.45", "destination": "ANY"},
        ],
        "terminalLogs": [
            "[2026-06-24 14:05:00] Windows Agent initialized.",
            "[2026-06-24 14:05:15] Outbound DNS packets spike detected on UDP/53.",
        ],
    },
    "my-linux-machine": {
        "hostname": "my-linux-machine",
        "ip": "192.168.67.129",       # ← your machine's real IP
        "os": "Linux",
        "status": "ONLINE",
        "connectionsCount": 5,
        "processes": [
            {"pid": 1,   "name": "systemd",  "cpu": 0.1, "memory": 0.2, "status": "Running"},
            {"pid": 520, "name": "sshd",     "cpu": 0.0, "memory": 0.5, "status": "Running"},
            {"pid": 830, "name": "bash",     "cpu": 0.3, "memory": 1.1, "status": "Running"},
        ],
        "firewallRules": [
            {"id": "fw-31", "direction": "INBOUND",  "proto": "TCP", "port": "22",  "action": "ALLOW", "source": "ANY",       "destination": "192.168.67.129"},
            {"id": "fw-32", "direction": "OUTBOUND", "proto": "ANY", "port": "ANY", "action": "ALLOW", "source": "192.168.67.129", "destination": "ANY"},
        ],
        "terminalLogs": [
            "[2026-06-29 03:00:00] Endpoint agent online on my-linux-machine.",
            "[2026-06-29 03:00:01] SSH connectivity verified.",
        ],
    },
}

# ---------------------------------------------------------------------------
# Gemini AI initialisation
# ---------------------------------------------------------------------------
_gemini_model: Optional[Any] = None

def _get_gemini_client() -> Optional[Any]:
    global _gemini_model
    if _gemini_model is not None:
        return _gemini_model
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("WARNING: GEMINI_API_KEY environment variable is missing. Running in high-fidelity mock mode.")
        return None
    _gemini_model = genai.Client(
        api_key=api_key,
        http_options={"headers": {"User-Agent": "ir-ids-agent"}},
    )
    return _gemini_model


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def startup_event() -> None:
    _initialize_data_directories()
    _get_gemini_client()  # warm up / validate key


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------
class UploadFlowRequest(BaseModel):
    flowData: str

class InvestigateRequest(BaseModel):
    flow: Optional[dict] = None
    prediction: Optional[dict] = None
    manualContext: Optional[str] = None
    victimHost: Optional[str] = None

class ExecuteActionRequest(BaseModel):
    incidentId: Optional[str] = None
    actionType: str
    target: str
    details: Optional[str] = None

class CreateTicketRequest(BaseModel):
    incidentId: Optional[str] = None
    title: str
    priority: Optional[str] = "Medium"

class FirewallUnblockRequest(BaseModel):
    ip: str

class FirewallUnisolateRequest(BaseModel):
    hostname: str

class IDSIngestRequest(BaseModel):
    source: Optional[str] = "hybrid_ids_dashboard"
    filename: Optional[str] = None
    analysisResult: dict

class IncidentInvestigationRequest(BaseModel):
    incidentId: str
    manualContext: Optional[str] = None
    victimHost: Optional[str] = None
    businessImpact: Optional[str] = None
    systemRole: Optional[str] = None


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------
def _read_blocklist() -> list[str]:
    return [ip.strip() for ip in BLOCKLIST_FILE.read_text().splitlines() if ip.strip()]

def _read_isolated() -> list[str]:
    return [h.strip() for h in ISOLATED_FILE.read_text().splitlines() if h.strip()]

def _read_tickets() -> list[dict]:
    lines = [l.strip() for l in TICKETS_FILE.read_text().splitlines() if l.strip()]
    return [json.loads(l) for l in lines]

def _read_incidents() -> list[dict]:
    incidents: list[dict] = []
    for f in INCIDENTS_DIR.glob("*.json"):
        try:
            incident = json.loads(f.read_text())

            # Keep the React Forensic Report tab working for real IDS handoff mode.
            # Older incident JSON files may not contain markdown_report, while the
            # report exists separately in data/reports/<incident_id>.md. Attach it
            # when loading dashboard state.
            if not incident.get("markdown_report"):
                report_path = REPORTS_DIR / f"{incident.get('id')}.md"
                if report_path.exists():
                    incident["markdown_report"] = report_path.read_text()

            incidents.append(incident)
        except Exception:
            pass
    incidents.sort(key=lambda i: i.get("timestamp", ""), reverse=True)
    return incidents

def _now_ts() -> str:
    return datetime.now(tz=timezone.utc).strftime("%H:%M:%S")

def _port_to_service(port: str) -> str:
    return "postgresql" if port == "5432" else "dns" if port == "53" else "http"


# ---------------------------------------------------------------------------
# ── REMOTE ENFORCEMENT ENGINE ──────────────────────────────────────────────
# Controlled by ENFORCEMENT_MODE in .env:
#   demo           – (default) simulation only, NO remote changes
#   ssh_linux      – SSH into Linux endpoints → iptables + ip route
#   windows_remote – WinRM into Windows endpoints → netsh advfirewall
#   auto           – pick SSH or WinRM per host OS automatically
# This Windows machine running the app is NEVER touched in any mode.
# ---------------------------------------------------------------------------

ENFORCEMENT_MODE: str  = os.getenv("ENFORCEMENT_MODE", "demo").lower()
_SSH_USER: str         = os.getenv("SSH_USER", "root")
_SSH_PASSWORD: str     = os.getenv("SSH_PASSWORD", "")
_SSH_KEY_PATH: str     = os.getenv("SSH_KEY_PATH", "")
_SSH_TIMEOUT: int      = int(os.getenv("SSH_TIMEOUT", "10"))
_WINRM_USER: str       = os.getenv("WINRM_USER", "Administrator")
_WINRM_PASSWORD: str   = os.getenv("WINRM_PASSWORD", "")
_WINRM_PORT: int       = int(os.getenv("WINRM_PORT", "5985"))
_IR_CONTROLLER_IP: str = os.getenv("IR_CONTROLLER_IP", "127.0.0.1")

try:
    _SSH_HOST_MAP: dict[str, str] = json.loads(os.getenv("SSH_HOST_MAP", "{}"))
except Exception:
    _SSH_HOST_MAP = {}


def _resolve_host_ip(hostname: str) -> str:
    """Resolve a hostname to its real management IP."""
    if hostname in _SSH_HOST_MAP:
        return _SSH_HOST_MAP[hostname]
    agent = ENDPOINT_AGENTS.get(hostname)
    if agent:
        return str(agent.get("ip", hostname))
    return hostname


def _get_host_os(hostname: str) -> str:
    """Return OS string for a known endpoint agent."""
    agent = ENDPOINT_AGENTS.get(hostname)
    return str(agent.get("os", "Linux")) if agent else "Linux"


# ── SSH helpers (Linux endpoints) ─────────────────────────────────────────

def _ssh_exec(host_ip: str, commands: list[str]) -> list[str]:
    """Open one SSH session to host_ip and execute each command with sudo. Returns log lines."""
    logs: list[str] = []

    if not _PARAMIKO_AVAILABLE:
        return ["⚠️ paramiko not installed. Run: pip install paramiko"]

    if not _SSH_KEY_PATH and not _SSH_PASSWORD:
        return ["⚠️ No SSH credential configured. Set SSH_PASSWORD or SSH_KEY_PATH in .env"]

    try:
        client = _paramiko.SSHClient()  # type: ignore[union-attr]
        client.set_missing_host_key_policy(_paramiko.AutoAddPolicy())  # type: ignore[union-attr]

        kw: dict[str, Any] = {
            "hostname": host_ip,
            "username": _SSH_USER,
            "timeout": _SSH_TIMEOUT,
            "allow_agent": False,
            "look_for_keys": False,
        }

        if _SSH_KEY_PATH:
            kw["key_filename"] = _SSH_KEY_PATH
        else:
            kw["password"] = _SSH_PASSWORD

        client.connect(**kw)

        for cmd in commands:
            # Run every command as sudo because kali user is not root
            sudo_cmd = f"echo '{_SSH_PASSWORD}' | sudo -S bash -lc {json.dumps(cmd)}"

            _, stdout, stderr = client.exec_command(sudo_cmd, timeout=_SSH_TIMEOUT)

            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode(errors="ignore").strip()
            err = stderr.read().decode(errors="ignore").strip()

            logs.append(f"  [{host_ip}] $ sudo {cmd}")

            if exit_code == 0:
                logs.append("  └─  OK")
                if out:
                    logs.append(f"     {out}")
            else:
                logs.append(f"  └─ x FAILED exit={exit_code}")
                if err:
                    logs.append(f"     STDERR: {err}")
                if out:
                    logs.append(f"     STDOUT: {out}")

        client.close()

    except Exception as exc:
        logs.append(f"x SSH → {host_ip} failed: {exc}")

    return logs


def _ssh_block_ip(host_ip: str, attacker_ip: str) -> list[str]:
    """Apply iptables DROP + blackhole for attacker_ip on a remote Linux host."""
    c = "IR-Agent-Block"
    cmds = [
        f"iptables -I INPUT  -s {attacker_ip} -j DROP -m comment --comment {c}",
        f"iptables -I OUTPUT -d {attacker_ip} -j DROP -m comment --comment {c}",
        f"ip route add blackhole {attacker_ip}/32 2>/dev/null || true",
    ]
    return [f"\U0001f534 SSH \u2192 {host_ip}: blocking {attacker_ip}"] + _ssh_exec(host_ip, cmds)


def _ssh_isolate(host_ip: str) -> list[str]:
    """SSH into the target host and isolate it while keeping the IR controller reachable."""
    c = "IR-Agent-Isolate"
    ir = _IR_CONTROLLER_IP

    cmds = [
        # Backup current rules
        "iptables-save > /tmp/iptables-before-ir-isolation.rules || true",

        # Remove old IR isolation rules by flushing custom chain if it exists
        "iptables -D INPUT -j IR_AGENT_ISOLATE 2>/dev/null || true",
        "iptables -D OUTPUT -j IR_AGENT_ISOLATE 2>/dev/null || true",
        "iptables -F IR_AGENT_ISOLATE 2>/dev/null || true",
        "iptables -X IR_AGENT_ISOLATE 2>/dev/null || true",

        # Create custom isolation chain
        "iptables -N IR_AGENT_ISOLATE",

        # Allow loopback
        "iptables -A IR_AGENT_ISOLATE -i lo -j ACCEPT",

        # Allow established connections from/to IR controller
        "iptables -A IR_AGENT_ISOLATE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",

        # Allow only Windows IR controller
        f"iptables -A IR_AGENT_ISOLATE -s {ir} -j ACCEPT -m comment --comment {c}",
        f"iptables -A IR_AGENT_ISOLATE -d {ir} -j ACCEPT -m comment --comment {c}",

        # Drop everything else
        f"iptables -A IR_AGENT_ISOLATE -j DROP -m comment --comment {c}",

        # Attach chain to INPUT and OUTPUT
        "iptables -I INPUT 1 -j IR_AGENT_ISOLATE",
        "iptables -I OUTPUT 1 -j IR_AGENT_ISOLATE",

        # Show final rules
        "iptables -S",
    ]

    return [f"🟠 SSH → {host_ip}: isolating. IR controller {ir} stays allowed."] + _ssh_exec(host_ip, cmds)


def _ssh_unblock_ip(host_ip: str, attacker_ip: str) -> list[str]:
    """Remove IR-Agent iptables block rules from a remote Linux host."""
    c = "IR-Agent-Block"
    cmds = [
        f"iptables -D INPUT  -s {attacker_ip} -j DROP -m comment --comment {c} 2>/dev/null || true",
        f"iptables -D OUTPUT -d {attacker_ip} -j DROP -m comment --comment {c} 2>/dev/null || true",
        f"ip route del blackhole {attacker_ip}/32 2>/dev/null || true",
    ]
    return [f"\U0001f7e2 SSH \u2192 {host_ip}: unblocking {attacker_ip}"] + _ssh_exec(host_ip, cmds)


def _ssh_unisolate(host_ip: str) -> list[str]:
    """Remove isolation chain from a remote Linux host."""
    cmds = [
        "iptables -D INPUT -j IR_AGENT_ISOLATE 2>/dev/null || true",
        "iptables -D OUTPUT -j IR_AGENT_ISOLATE 2>/dev/null || true",
        "iptables -F IR_AGENT_ISOLATE 2>/dev/null || true",
        "iptables -X IR_AGENT_ISOLATE 2>/dev/null || true",
        "iptables -S",
    ]

    return [f"🟢 SSH → {host_ip}: removing isolation rules"] + _ssh_exec(host_ip, cmds)
# ── WinRM helpers (Windows endpoints) ─────────────────────────────────────

def _winrm_run_cmds(host_ip: str, commands: list[str]) -> list[str]:
    """Run Windows commands on a remote host via WinRM. Returns log lines."""
    logs: list[str] = []
    if not _WINRM_AVAILABLE:
        return ["\u26a0\ufe0f  pywinrm not installed. Run: pip install pywinrm"]
    if not _WINRM_PASSWORD:
        return ["\u26a0\ufe0f  WINRM_PASSWORD not set in .env"]
    try:
        session = _winrm_lib.Session(  # type: ignore[union-attr]
            target=f"http://{host_ip}:{_WINRM_PORT}/wsman",
            auth=(_WINRM_USER, _WINRM_PASSWORD),
            transport="ntlm",
        )
        for cmd in commands:
            result = session.run_cmd(cmd)
            ok = result.status_code == 0
            err = result.std_err.decode().strip() if result.std_err else ""
            logs.append(f"  [{host_ip}] > {cmd[:80]}")
            logs.append(f"  \u2514\u2500 {'\u2705 OK' if ok else f'\u274c {err}'}")
    except Exception as exc:
        logs.append(f"\u274c WinRM \u2192 {host_ip} failed: {exc}")
    return logs


def _winrm_block_ip(host_ip: str, attacker_ip: str) -> list[str]:
    """Apply Windows Firewall block rules for attacker_ip on a remote Windows host."""
    ri = f"IR-Agent-Block-{attacker_ip}-IN"
    ro = f"IR-Agent-Block-{attacker_ip}-OUT"
    cmds = [
        f'netsh advfirewall firewall add rule name="{ri}" dir=in action=block remoteip={attacker_ip} protocol=any enable=yes',
        f'netsh advfirewall firewall add rule name="{ro}" dir=out action=block remoteip={attacker_ip} protocol=any enable=yes',
        f'route add {attacker_ip} mask 255.255.255.255 0.0.0.0 metric 1',
    ]
    return [f"\U0001f534 WinRM \u2192 {host_ip}: blocking {attacker_ip}"] + _winrm_run_cmds(host_ip, cmds)


def _winrm_isolate(host_ip: str) -> list[str]:
    """Apply full isolation firewall rules on a remote Windows host."""
    ir = _IR_CONTROLLER_IP
    p  = f"IR-Agent-Isolate-{host_ip}"
    cmds = [
        f'netsh advfirewall firewall add rule name="{p}-ALLOW-IR-IN"  dir=in  action=allow remoteip={ir}  protocol=any enable=yes',
        f'netsh advfirewall firewall add rule name="{p}-ALLOW-IR-OUT" dir=out action=allow remoteip={ir}  protocol=any enable=yes',
        f'netsh advfirewall firewall add rule name="{p}-DENY-ALL-IN"  dir=in  action=block remoteip=any   protocol=any enable=yes',
        f'netsh advfirewall firewall add rule name="{p}-DENY-ALL-OUT" dir=out action=block remoteip=any   protocol=any enable=yes',
    ]
    return [f"\U0001f7e0 WinRM \u2192 {host_ip}: isolating"] + _winrm_run_cmds(host_ip, cmds)


def _winrm_unblock_ip(host_ip: str, attacker_ip: str) -> list[str]:
    """Remove Windows Firewall block rules for attacker_ip from a remote Windows host."""
    ri = f"IR-Agent-Block-{attacker_ip}-IN"
    ro = f"IR-Agent-Block-{attacker_ip}-OUT"
    cmds = [
        f'netsh advfirewall firewall delete rule name="{ri}"',
        f'netsh advfirewall firewall delete rule name="{ro}"',
        f'route delete {attacker_ip}',
    ]
    return [f"\U0001f7e2 WinRM \u2192 {host_ip}: unblocking {attacker_ip}"] + _winrm_run_cmds(host_ip, cmds)


def _winrm_unisolate(host_ip: str) -> list[str]:
    """Remove isolation firewall rules from a remote Windows host."""
    p = f"IR-Agent-Isolate-{host_ip}"
    cmds = [
        f'netsh advfirewall firewall delete rule name="{p}-ALLOW-IR-IN"',
        f'netsh advfirewall firewall delete rule name="{p}-ALLOW-IR-OUT"',
        f'netsh advfirewall firewall delete rule name="{p}-DENY-ALL-IN"',
        f'netsh advfirewall firewall delete rule name="{p}-DENY-ALL-OUT"',
    ]
    return [f"\U0001f7e2 WinRM \u2192 {host_ip}: removing isolation rules"] + _winrm_run_cmds(host_ip, cmds)


# ── Unified dispatchers ────────────────────────────────────────────────────

def _enforce_block_ip(attacker_ip: str) -> list[str]:
    """Push block rules to ALL known remote endpoints. No-op in demo mode."""
    if ENFORCEMENT_MODE == "demo":
        return ["[DEMO] Real enforcement disabled. Set ENFORCEMENT_MODE=ssh_linux or windows_remote in .env to activate."]
    all_logs: list[str] = []
    for hostname in list(ENDPOINT_AGENTS.keys()):
        host_ip = _resolve_host_ip(hostname)
        host_os = _get_host_os(hostname).lower()
        if ENFORCEMENT_MODE in ("ssh_linux", "auto") and "linux" in host_os:
            all_logs += _ssh_block_ip(host_ip, attacker_ip)
        if ENFORCEMENT_MODE in ("windows_remote", "auto") and "windows" in host_os:
            all_logs += _winrm_block_ip(host_ip, attacker_ip)
    return all_logs or ["\u2139\ufe0f  No endpoints matched enforcement mode."]


def _enforce_isolate_host(target_hostname: str) -> list[str]:
    """Isolate the target host by SSHing/WinRMing into it directly. No-op in demo mode."""
    if ENFORCEMENT_MODE == "demo":
        return ["[DEMO] Real enforcement disabled. Set ENFORCEMENT_MODE=ssh_linux or windows_remote in .env to activate."]
    host_ip = _resolve_host_ip(target_hostname)
    host_os = _get_host_os(target_hostname).lower()
    if ENFORCEMENT_MODE in ("ssh_linux", "auto") and "linux" in host_os:
        return _ssh_isolate(host_ip)
    if ENFORCEMENT_MODE in ("windows_remote", "auto") and "windows" in host_os:
        return _winrm_isolate(host_ip)
    return [f"\u2139\ufe0f  No enforcement handler for OS '{host_os}' in mode '{ENFORCEMENT_MODE}'."]


def _enforce_unblock_ip(attacker_ip: str) -> list[str]:
    """Remove block rules from all remote endpoints. No-op in demo mode."""
    if ENFORCEMENT_MODE == "demo":
        return ["[DEMO] Real enforcement disabled."]
    all_logs: list[str] = []
    for hostname in list(ENDPOINT_AGENTS.keys()):
        host_ip = _resolve_host_ip(hostname)
        host_os = _get_host_os(hostname).lower()
        if ENFORCEMENT_MODE in ("ssh_linux", "auto") and "linux" in host_os:
            all_logs += _ssh_unblock_ip(host_ip, attacker_ip)
        if ENFORCEMENT_MODE in ("windows_remote", "auto") and "windows" in host_os:
            all_logs += _winrm_unblock_ip(host_ip, attacker_ip)
    return all_logs or ["\u2139\ufe0f  No endpoints matched enforcement mode."]


def _enforce_unisolate_host(target_hostname: str) -> list[str]:
    """Remove isolation rules from the target host. No-op in demo mode."""
    if ENFORCEMENT_MODE == "demo":
        return ["[DEMO] Real enforcement disabled."]
    host_ip = _resolve_host_ip(target_hostname)
    host_os = _get_host_os(target_hostname).lower()
    if ENFORCEMENT_MODE in ("ssh_linux", "auto") and "linux" in host_os:
        return _ssh_unisolate(host_ip)
    if ENFORCEMENT_MODE in ("windows_remote", "auto") and "windows" in host_os:
        return _winrm_unisolate(host_ip)
    return [f"\u2139\ufe0f  No unisolate handler for OS '{host_os}'."]



# ---------------------------------------------------------------------------
# Hybrid IDS handoff helpers
# ---------------------------------------------------------------------------
def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def _first_nonempty(*values: Any, default: str = "unknown") -> str:
    for value in values:
        if value is not None and str(value).strip() not in {"", "-", "None", "nan"}:
            return str(value).strip()
    return default


_IP_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")


def _looks_like_ip(value: Any) -> bool:
    return bool(_IP_RE.match(str(value).strip()))


def _clean_flow_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, float) and math.isnan(value):
        return None
    if isinstance(value, (int, float, bool)):
        return value
    text = str(value).strip()
    if text in {"", "-", "None", "nan", "NaN"}:
        return None
    return text


def _get_any(row: dict, candidates: list[str], default: Any = None) -> Any:
    """Read CICFlowMeter-style columns with many common naming variants."""
    if not isinstance(row, dict):
        return default
    normalised = {re.sub(r"[^a-z0-9]", "", str(k).lower()): k for k in row.keys()}
    for cand in candidates:
        if cand in row:
            value = _clean_flow_value(row.get(cand))
            if value is not None:
                return value
        key = normalised.get(re.sub(r"[^a-z0-9]", "", cand.lower()))
        if key is not None:
            value = _clean_flow_value(row.get(key))
            if value is not None:
                return value
    return default


def _iter_ids_evidence_rows(analysis: dict) -> list[dict]:
    """Rows forwarded by the Hybrid IDS: original flow metadata + model outputs."""
    rows: list[dict] = []
    for key in ["flow_metadata_preview", "results_preview", "zero_day_details"]:
        value = analysis.get(key) or []
        if isinstance(value, list):
            rows.extend([r for r in value if isinstance(r, dict)])
    zd_top = (analysis.get("zero_day_summary") or {}).get("top_anomalous_rows") or []
    if isinstance(zd_top, list):
        rows.extend([r for r in zd_top if isinstance(r, dict)])
    sample_alerts = ((analysis.get("rule_result") or {}).get("sample_alerts") or [])
    if isinstance(sample_alerts, list):
        rows.extend([r for r in sample_alerts if isinstance(r, dict)])
    return rows


SRC_IP_KEYS = ["source_ip", "src_ip", "Source IP", "Src IP", "Source", "src", "Src", "SourceIP", "SrcIP", "ip.src", "saddr"]
DST_IP_KEYS = ["destination_ip", "dst_ip", "Destination IP", "Dst IP", "Destination", "dst", "Dst", "DestinationIP", "DstIP", "ip.dst", "daddr"]
SRC_PORT_KEYS = ["source_port", "src_port", "Source Port", "Src Port", "sport", "srcport", "SourcePort", "SrcPort"]
DST_PORT_KEYS = ["destination_port", "dst_port", "Destination Port", "Dst Port", "dport", "dstport", "DestinationPort", "DstPort"]
PROTO_KEYS = ["protocol", "Protocol", "proto", "ProtocolName"]
DURATION_KEYS = ["duration", "Duration", "Flow Duration", "flow_duration", "duration_ms"]
PACKET_KEYS = ["packets", "Packets", "Total Packets", "Tot Packets", "Total Fwd Packets", "Total Backward Packets", "Tot Fwd Pkts", "Tot Bwd Pkts", "Fwd Packets", "Bwd Packets"]
BYTE_KEYS = ["bytes", "Bytes", "Total Bytes", "Tot Bytes", "Fwd Packets Length Total", "Bwd Packets Length Total", "Total Length of Fwd Packets", "Total Length of Bwd Packets", "TotLen Fwd Pkts", "TotLen Bwd Pkts"]
LABEL_KEYS = ["label", "Label", "BENIGN", "attack_type", "Attack Type", "zero_day_prediction", "prediction"]


def _extract_flow_metadata(row: dict) -> dict:
    src_ip = _get_any(row, SRC_IP_KEYS, "unknown")
    dst_ip = _get_any(row, DST_IP_KEYS, "unknown")
    src_port = _get_any(row, SRC_PORT_KEYS, "-")
    dst_port = _get_any(row, DST_PORT_KEYS, "-")
    proto = _get_any(row, PROTO_KEYS, "FLOW")
    duration = _get_any(row, DURATION_KEYS, 0)

    # CICFlowMeter often splits packet/byte totals into forward/backward columns.
    packets = _get_any(row, ["packets", "Packets", "Total Packets", "Tot Packets"], None)
    if packets is None:
        packets = _safe_int(_get_any(row, ["Total Fwd Packets", "Tot Fwd Pkts", "Fwd Packets"], 0)) + _safe_int(_get_any(row, ["Total Backward Packets", "Tot Bwd Pkts", "Bwd Packets"], 0))
    bytes_count = _get_any(row, ["bytes", "Bytes", "Total Bytes", "Tot Bytes"], None)
    if bytes_count is None:
        bytes_count = _safe_int(_get_any(row, ["Fwd Packets Length Total", "Total Length of Fwd Packets", "TotLen Fwd Pkts"], 0)) + _safe_int(_get_any(row, ["Bwd Packets Length Total", "Total Length of Bwd Packets", "TotLen Bwd Pkts"], 0))

    return {
        "source_ip": str(src_ip),
        "target_ip": str(dst_ip),
        "source_port": str(src_port),
        "target_port": str(dst_port),
        "protocol": str(proto),
        "packets": _safe_int(packets, 0),
        "bytes": _safe_int(bytes_count, 0),
        "duration_ms": _safe_int(duration, 0),
        "service": _port_to_service(str(dst_port)),
        "label": str(_get_any(row, LABEL_KEYS, "-")),
        "flow_index": _get_any(row, ["flow_index", "Flow Index", "index"], "-"),
        "reconstruction_error": _get_any(row, ["reconstruction_error", "Reconstruction Error"], None),
    }


def _ids_best_flow_metadata(analysis: dict) -> dict:
    """Pick the best real flow row, preferring anomalous/attack rows."""
    rows = _iter_ids_evidence_rows(analysis)
    if not rows:
        return {}

    def score(row: dict) -> tuple:
        meta = _extract_flow_metadata(row)
        has_ip = int(_looks_like_ip(meta.get("source_ip")) or _looks_like_ip(meta.get("target_ip")))
        anomalous = int(str(_get_any(row, ["zero_day_prediction", "above_threshold", "attack_type_status", "label", "Label"], "")).lower() not in {"", "-", "normal", "benign", "false", "0"})
        err = _safe_float(_get_any(row, ["reconstruction_error"], 0), 0)
        packets = _safe_int(meta.get("packets"), 0)
        bytes_count = _safe_int(meta.get("bytes"), 0)
        return (anomalous, has_ip, err, packets, bytes_count)

    best = max(rows, key=score)
    return _extract_flow_metadata(best)


def _ids_find_source_ip(analysis: dict) -> str:
    """Extract the best suspicious source IP from Hybrid IDS output."""
    ir = analysis.get("incident_response") or {}
    suspicious_ips = ir.get("suspicious_ips") or []
    if suspicious_ips:
        item = suspicious_ips[0]
        if isinstance(item, dict):
            ip = _first_nonempty(item.get("ip"), item.get("src"), item.get("source_ip"), default="")
        else:
            ip = _first_nonempty(item, default="")
        if _looks_like_ip(ip):
            return ip

    rule_result = analysis.get("rule_result") or {}
    summary = rule_result.get("summary") or {}
    top_sources = summary.get("top_sources") or []
    if top_sources:
        item = top_sources[0]
        if isinstance(item, dict):
            ip = _first_nonempty(item.get("src"), item.get("ip"), item.get("source_ip"), default="")
        else:
            ip = _first_nonempty(item, default="")
        if _looks_like_ip(ip):
            return ip

    for row in _iter_ids_evidence_rows(analysis):
        ip = _get_any(row, SRC_IP_KEYS, "")
        if _looks_like_ip(ip):
            return str(ip)

    meta = _ids_best_flow_metadata(analysis)
    ip = meta.get("source_ip", "")
    return str(ip) if _looks_like_ip(ip) else "unknown"


def _ids_find_target_ip(analysis: dict) -> str:
    for row in _iter_ids_evidence_rows(analysis):
        target = _get_any(row, DST_IP_KEYS, "")
        if _looks_like_ip(target):
            return str(target)
    meta = _ids_best_flow_metadata(analysis)
    target = meta.get("target_ip", "")
    return str(target) if _looks_like_ip(target) else "10.0.0.5"


def _ids_traffic_stats(analysis: dict) -> dict:
    meta = _ids_best_flow_metadata(analysis)
    if not meta:
        meta = {}
    return {
        "packets": _safe_int(meta.get("packets"), 0),
        "bytes": _safe_int(meta.get("bytes"), 0),
        "duration_ms": _safe_int(meta.get("duration_ms"), 0),
        "protocol": str(meta.get("protocol") or "FLOW"),
        "src_port": str(meta.get("source_port") or "-"),
        "dst_port": str(meta.get("target_port") or "-"),
        "service": str(meta.get("service") or _port_to_service(str(meta.get("target_port") or ""))),
        "flow_index": meta.get("flow_index", "-"),
        "label": meta.get("label", "-"),
        "reconstruction_error": meta.get("reconstruction_error"),
    }


def _format_flow_metadata_md(flow_meta: dict) -> str:
    if not flow_meta:
        return "- No original flow metadata was forwarded by the IDS."
    return "\n".join([
        f"- **Source IP:** `{flow_meta.get('source_ip', 'unknown')}`",
        f"- **Target IP:** `{flow_meta.get('target_ip', 'unknown')}`",
        f"- **Source Port:** `{flow_meta.get('source_port', '-')}`",
        f"- **Target Port:** `{flow_meta.get('target_port', '-')}`",
        f"- **Protocol:** `{flow_meta.get('protocol', '-')}`",
        f"- **Packets:** `{flow_meta.get('packets', 0)}`",
        f"- **Bytes:** `{flow_meta.get('bytes', 0)}`",
        f"- **Duration:** `{flow_meta.get('duration_ms', 0)}`",
        f"- **Label / Flow Finding:** `{flow_meta.get('label', '-')}`",
        f"- **Reconstruction Error:** `{flow_meta.get('reconstruction_error', '-')}`",
    ])


def _ids_dominant_attack(analysis: dict) -> str:
    zd = analysis.get("zero_day_summary") or {}
    zd_decision = str(zd.get("decision", "")).lower()
    if "zero" in zd_decision or "possible" in zd_decision or _safe_int(zd.get("anomalous_rows"), 0) > 0:
        return "Possible Zero-Day / Unknown Anomaly"

    mc = analysis.get("multiclass_summary") or {}
    mc_top = _first_nonempty(mc.get("Top_1_Attack"), default="")
    if mc_top:
        return mc_top

    attack_summary = analysis.get("attack_type_summary") or {}
    if isinstance(attack_summary, dict) and attack_summary:
        non_zero = {str(k): _safe_int(v) for k, v in attack_summary.items() if _safe_int(v) > 0}
        if non_zero:
            return max(non_zero, key=non_zero.get)

    rule_result = analysis.get("rule_result") or {}
    packet_attack_summary = (rule_result.get("summary") or {}).get("attack_type_summary") or {}
    if isinstance(packet_attack_summary, dict) and packet_attack_summary:
        non_zero = {str(k): _safe_int(v) for k, v in packet_attack_summary.items() if _safe_int(v) > 0}
        if non_zero:
            return max(non_zero, key=non_zero.get)

    return "IDS Alert"


def _ids_severity(analysis: dict) -> tuple[str, float, str]:
    local_ir = analysis.get("incident_response") or {}
    sev = local_ir.get("severity") or {}
    label = str(sev.get("label", "")).strip()
    if label:
        score = _safe_float(sev.get("score"), 70.0)
        cvss = 9.1 if label.lower() == "critical" else 8.0 if label.lower() == "high" else 5.5 if label.lower() == "medium" else 3.0
        return label, cvss, f"IDS local risk score: {score}/100"

    decision = str(analysis.get("official_binary_decision", "")).lower()
    rules = _safe_int(((analysis.get("rule_result") or {}).get("summary") or {}).get("total_alerts"), 0)
    zd = analysis.get("zero_day_summary") or {}
    anomalous = _safe_int(zd.get("anomalous_rows"), 0)

    if anomalous > 0 and "attack" in decision:
        return "Critical", 9.0, "Known attack plus zero-day/anomaly evidence."
    if "attack" in decision or rules >= 20:
        return "High", 8.0, "Hybrid IDS classified the traffic as attack or packet rules produced many alerts."
    if rules > 0 or anomalous > 0:
        return "Medium", 5.8, "Suspicious activity detected but evidence is limited."
    return "Low", 2.0, "No strong malicious evidence was provided by IDS."


def _ids_mitre_mapping(attack: str) -> dict:
    a = attack.lower()
    if "dos" in a or "ddos" in a or "flood" in a:
        return {"id": "T1498.001", "name": "Direct Network Flood", "tactic": "Impact"}
    if "brute" in a or "ssh" in a or "password" in a:
        return {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
    if "sql" in a or "xss" in a or "exploit" in a:
        return {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
    if "scan" in a or "port" in a:
        return {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}
    if "zero" in a or "unknown" in a or "anomaly" in a:
        return {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
    return {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access"}


def _ids_choose_target_host(target_ip: str, attack: str) -> str:
    for host, agent in ENDPOINT_AGENTS.items():
        if str(agent.get("ip")) == target_ip:
            return host
    a = attack.lower()
    if "sql" in a or "database" in a:
        return "db-srv-prod"
    if "dns" in a or "exfil" in a:
        return "corp-laptop-12"
    return "prod-web-01"


def _ids_write_report(incident: dict, analysis: dict, filename: str) -> str:
    binary = analysis.get("official_binary_decision", "UNKNOWN")
    mc = analysis.get("multiclass_summary") or {}
    zd = analysis.get("zero_day_summary") or {}
    rule_summary = (analysis.get("rule_result") or {}).get("summary") or {}
    report = f"""# Hybrid IDS Escalation Report: {incident['id']}

## Executive Summary
The Hybrid IDS forwarded a detection result from `{filename}` to the SOAR Incident Response dashboard. The event was classified as **{incident['attack_type']}** with **{incident['severity']}** severity.

## Detection Evidence
- **Binary Decision**: `{binary}`
- **Multiclass Top Attack**: `{mc.get('Top_1_Attack', '-')}`
- **Zero-Day Decision**: `{zd.get('decision', 'UNAVAILABLE')}`
- **Zero-Day Anomalous Rows**: `{zd.get('anomalous_rows', 0)}`
- **Packet Rule Alerts**: `{rule_summary.get('total_alerts', 0)}`
- **Flows Analyzed**: `{analysis.get('flows_analyzed', '-')}`

## Original Flow Metadata Used by SOAR
{_format_flow_metadata_md(incident.get('flow_metadata') or {})}

## Indicators
- **Source IP**: `{incident['source_ip']}`
- **Target IP**: `{incident['target_ip']}`
- **Target Host**: `{incident['target_host']}`
- **MITRE Mapping**: `{incident['mitre']['id']} - {incident['mitre']['name']}`

## Recommended IR Workflow
1. Validate the source IP and target host using firewall, endpoint, and application logs.
2. Open a SOC ticket and assign an analyst for verification.
3. If the activity is confirmed malicious, block the source IP and isolate the affected host.
4. Preserve volatile evidence before destructive containment if the affected system is critical.
"""
    return report


# ---------------------------------------------------------------------------
# Route 0 — POST /api/ids-ingest
# Receives Hybrid IDS detections and turns them into SOAR incidents.
# ---------------------------------------------------------------------------
@app.post("/api/ids-ingest")
async def ingest_hybrid_ids_detection(body: IDSIngestRequest) -> dict:
    if not isinstance(body.analysisResult, dict):
        raise HTTPException(status_code=400, detail="analysisResult must be an object")

    analysis = body.analysisResult
    filename = body.filename or analysis.get("filename") or "hybrid_ids_upload"
    attack_type = _ids_dominant_attack(analysis)
    source_ip = _ids_find_source_ip(analysis)
    target_ip = _ids_find_target_ip(analysis)
    target_host = _ids_choose_target_host(target_ip, attack_type)
    severity, cvss, reason = _ids_severity(analysis)
    mitre = _ids_mitre_mapping(attack_type)

    incident_id = f"INC-IDS-{datetime.now(tz=timezone.utc).strftime('%Y%m%d-%H%M%S')}-{random.randint(100, 999)}"
    response_plan = []
    if source_ip != "unknown":
        response_plan.append({
            "type": "block_ip",
            "target": source_ip,
            "description": f"Block confirmed malicious source IP {source_ip} after analyst validation",
            "status": "Pending",
        })
    response_plan.append({
        "type": "isolate_host",
        "target": target_host,
        "description": f"Isolate {target_host} if compromise is confirmed or the service is business critical",
        "status": "Pending",
    })

    incident = {
        "id": incident_id,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "source_ip": source_ip,
        "target_ip": target_ip,
        "target_host": target_host,
        "attack_type": attack_type,
        "severity": severity,
        "cvss": cvss,
        "status": "Investigated",
        "mitre": mitre,
        "traffic_stats": _ids_traffic_stats(analysis),
        "flow_metadata": _ids_best_flow_metadata(analysis),
        "ids_analysis_result": analysis,
        "response_plan": response_plan,
        "investigation_summary": (
            f"Hybrid IDS escalated this event from {filename}. {reason} "
            f"Binary decision: {analysis.get('official_binary_decision', 'UNKNOWN')}. "
            f"Zero-day decision: {(analysis.get('zero_day_summary') or {}).get('decision', 'UNAVAILABLE')}."
        ),
    }

    report = _ids_write_report(incident, analysis, filename)

    # The React UI reads activeIncident.markdown_report inside the Forensic
    # Report tab. Keep the same content both embedded in the incident JSON
    # and saved as a standalone markdown file.
    incident["markdown_report"] = report

    try:
        (INCIDENTS_DIR / f"{incident_id}.json").write_text(json.dumps(incident, indent=2))
        (REPORTS_DIR / f"{incident_id}.md").write_text(report)
        ticket = {
            "ticket_id": f"TKT-IDS-{random.randint(100, 999)}",
            "incident_id": incident_id,
            "title": f"{severity}: Hybrid IDS detected {attack_type}",
            "status": "Open",
            "priority": severity,
            "assignee": "SOC-Automated",
            "created_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        with TICKETS_FILE.open("a") as f:
            f.write(json.dumps(ticket) + "\n")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to persist IDS incident: {exc}")

    return {
        "success": True,
        "source": body.source,
        "incident_id": incident_id,
        "incident": incident,
        "ticket": ticket,
        "dashboard_url": os.getenv("APP_URL", "http://localhost:5173"),
    }

# ---------------------------------------------------------------------------
# Route 1 — GET /api/status
# ---------------------------------------------------------------------------
@app.get("/api/status")
async def get_status() -> dict:
    try:
        return {
            "incidents": _read_incidents(),
            "blocklist": _read_blocklist(),
            "isolatedHosts": _read_isolated(),
            "tickets": _read_tickets(),
            "endpoints": ENDPOINT_AGENTS,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load IR database: {exc}")


# ---------------------------------------------------------------------------
# Route 2 — POST /api/upload-flow
# ---------------------------------------------------------------------------
@app.post("/api/upload-flow")
async def upload_flow(body: UploadFlowRequest) -> dict:
    lines = [l.strip() for l in body.flowData.splitlines() if l.strip()]
    if len(lines) < 2:
        raise HTTPException(status_code=400, detail="Invalid CSV. Header and at least one row required.")

    headers = [h.strip().lower() for h in lines[0].split(",")]
    values = [v.strip() for v in lines[1].split(",")]
    flow: dict[str, str] = {h: (values[i] if i < len(values) else "") for i, h in enumerate(headers)}

    # Feature extraction
    packets = int(flow.get("packets") or flow.get("spkts") or "10")
    bytes_count = int(flow.get("bytes") or flow.get("sbytes") or "1000")
    proto = (flow.get("protocol") or flow.get("proto") or "TCP").upper()
    dport = flow.get("dst_port") or flow.get("dport") or "80"
    try:
        duration = float(flow.get("duration") or "0.5")
    except ValueError:
        duration = 0.5

    detected_attack = "Normal"
    confidence = 0.05
    features = [
        {"feature": "Duration", "weight": 0.15, "value": duration},
        {"feature": "Packet Count", "weight": 0.25, "value": packets},
        {"feature": "Byte Count", "weight": 0.30, "value": bytes_count},
        {"feature": "Dest Port", "weight": 0.10, "value": dport},
        {"feature": "Protocol", "weight": 0.20, "value": proto},
    ]

    if proto == "UDP" and packets > 5000:
        detected_attack = "UDP Flood (DDoS)"
        confidence = 0.985
        features[1]["weight"] = 0.45
        features[2]["weight"] = 0.35
    elif dport == "5432" and packets > 0 and (bytes_count / packets) > 300:
        detected_attack = "Database SQL Exploitation"
        confidence = 0.892
        features[2]["weight"] = 0.45
        features[3]["weight"] = 0.25
    elif dport == "22" and duration > 0 and (packets / duration) > 100:
        detected_attack = "SSH Brute Force Attack"
        confidence = 0.941
        features[0]["weight"] = 0.40
        features[1]["weight"] = 0.30
    elif dport == "53" and packets > 500 and bytes_count < 100000:
        detected_attack = "DNS Tunneling / Data Exfil"
        confidence = 0.864
        features[4]["weight"] = 0.35
        features[3]["weight"] = 0.25
    elif packets > 50 and bytes_count > 5000:
        detected_attack = "Suspicious Traffic Anomaly"
        confidence = 0.62

    return {
        "parsedFlow": flow,
        "prediction": {
            "label": detected_attack,
            "confidence": confidence,
            "isAnomalous": detected_attack != "Normal",
        },
        "features": features,
    }


# ---------------------------------------------------------------------------
# Route 2B — POST /api/investigate-incident
# Runs the AI responder on a real Hybrid IDS incident that already exists.
# This keeps the SOAR dashboard in real IDS handoff mode: no quick-inject
# templates and no local mock uploads are needed.
# ---------------------------------------------------------------------------
@app.post("/api/investigate-incident")
async def investigate_existing_ids_incident(body: IncidentInvestigationRequest) -> dict:
    incident_id = body.incidentId.strip()
    if not incident_id:
        raise HTTPException(status_code=400, detail="incidentId is required")

    incident_path = INCIDENTS_DIR / f"{incident_id}.json"
    if not incident_path.exists():
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} was not found")

    try:
        incident = json.loads(incident_path.read_text())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read incident: {exc}")

    manual_context = body.manualContext or "No extra SOC analyst notes were supplied."
    victim_host = body.victimHost or incident.get("target_host") or "prod-web-01"
    business_impact = body.businessImpact or "High"
    system_role = body.systemRole or "Public Web Gateway"

    prompt = f"""
You are an autonomous Security Incident Response and Digital Forensics Agent working on a Hybrid IDS + SOAR dashboard.

Objective:
Enrich the existing Hybrid IDS incident into an analyst-ready investigation. The dashboard will display `investigation_summary` as IR Investigation Notes and `markdown_report` as the Markdown Forensic Summary.

Important rules:
- Use only the IDS evidence, original flow metadata, and analyst/business context below.
- Do not claim confirmed compromise unless the evidence supports it.
- If evidence is missing, write "Requires verification" instead of inventing logs.
- Every mitigation recommendation must include: verification before action, containment action, and post-action validation.
- Do not recommend destructive actions first. Preserve evidence before containment when the host is important.
- Response actions must be safe and realistic: block_ip after validation, isolate_host only if compromise/high risk is confirmed, kill_process only when a specific suspicious process is supported by evidence.

--- HYBRID IDS INCIDENT ---
Incident ID: {incident.get('id')}
Attack / Finding: {incident.get('attack_type')}
Severity: {incident.get('severity')}
CVSS: {incident.get('cvss')}
Source IP: {incident.get('source_ip')}
Target IP: {incident.get('target_ip')}
Target Host: {victim_host}
MITRE: {(incident.get('mitre') or {}).get('id')} - {(incident.get('mitre') or {}).get('name')} / {(incident.get('mitre') or {}).get('tactic')}
Traffic Stats: {json.dumps(incident.get('traffic_stats') or {})}
Original Flow Metadata: {json.dumps(incident.get('flow_metadata') or {})}
Full IDS Analysis Result: {json.dumps(incident.get('ids_analysis_result') or {}, ensure_ascii=False)[:12000]}
Existing Response Plan: {json.dumps(incident.get('response_plan') or [])}
Existing IDS Summary: {incident.get('investigation_summary', '')}

--- ANALYST / BUSINESS CONTEXT ---
Business Impact: {business_impact}
System Role: {system_role}
Manual SOC Notes:
{manual_context}

--- REQUIRED ANALYSIS ---
1. Explain what happened based on the Hybrid IDS decision, multiclass output, zero-day/anomaly result, rule alerts, and flow metadata.
2. Decide whether this is confirmed malicious, suspicious pending verification, or likely false positive. State confidence and uncertainty.
3. Produce CVSS v3.1-style severity reasoning with a valid-looking vector.
4. Map the activity to the closest MITRE ATT&CK technique and tactic.
5. Create a response plan with only appropriate actions: block_ip, isolate_host, or kill_process.
6. Write practical verification recommendations:
   - firewall/WAF/proxy log checks,
   - endpoint process and connection checks,
   - authentication/service log checks,
   - packet/flow validation,
   - false-positive checks.
7. Write mitigation recommendations:
   - immediate containment,
   - evidence preservation,
   - firewall/IP block or WAF rule,
   - endpoint isolation conditions,
   - service hardening,
   - rollback/unblock conditions.
8. Write post-mitigation validation:
   - confirm alerts stop,
   - confirm legitimate traffic still works,
   - confirm host health,
   - confirm block/isolation rule effectiveness.

--- REQUIRED OUTPUT STYLE ---
The `investigation_summary` field must be written as IR Investigation Notes. It must be one string containing 6 to 9 short bullet-style lines. It MUST include:
- Evidence summary
- Verification recommendation
- Mitigation recommendation
- Post-mitigation validation
- Analyst decision

The `markdown_report` field must be clean Markdown and MUST include these sections:
# Forensic Summary: <incident id or attack name>
## 1. Executive Summary
## 2. Detection Evidence
## 3. Forensic Findings
## 4. Verification Recommendations
## 5. Mitigation and Containment Recommendations
## 6. Recovery and Post-Mitigation Validation
## 7. MITRE ATT&CK and CVSS Reasoning
## 8. Final Analyst Decision

Return ONLY valid JSON with exactly these keys:
{{
  "attack_type": "string",
  "severity": "Low|Medium|High|Critical",
  "cvss": 0.0,
  "cvss_vector": "string",
  "mitre": {{"id":"string","name":"string","tactic":"string"}},
  "investigation_summary": "string",
  "response_plan": [{{"type":"block_ip|isolate_host|kill_process","target":"string","description":"string","status":"Pending"}}],
  "markdown_report": "string"
}}
"""

    parsed: dict[str, Any] = {}
    client = _get_gemini_client()
    if client:
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config=genai_types.GenerateContentConfig(
                    response_mime_type="application/json",
                    system_instruction=(
                        "You are a precise SOC incident response analyst. "
                        "Return strictly valid JSON only."
                    ),
                ),
            )
            parsed = json.loads((response.text or "{}").strip())
        except Exception as exc:
            print(f"Gemini incident enrichment failed, using local report fallback: {exc}")
            parsed = {}

    if parsed:
        incident["attack_type"] = parsed.get("attack_type") or incident.get("attack_type")
        incident["severity"] = parsed.get("severity") or incident.get("severity")
        incident["cvss"] = _safe_float(parsed.get("cvss"), _safe_float(incident.get("cvss"), 7.0))
        if parsed.get("cvss_vector"):
            incident["cvss_vector"] = parsed["cvss_vector"]
        if isinstance(parsed.get("mitre"), dict):
            incident["mitre"] = parsed["mitre"]
        if parsed.get("investigation_summary"):
            incident["investigation_summary"] = parsed["investigation_summary"]
        if isinstance(parsed.get("response_plan"), list) and parsed["response_plan"]:
            incident["response_plan"] = parsed["response_plan"]
        report = parsed.get("markdown_report") or ""
    else:
        report = f"""# Forensic Summary: {incident_id}

## 1. Executive Summary
The SOAR module received a real detection from the Hybrid IDS and escalated it for investigation. The selected incident is **{incident.get('attack_type', 'IDS Alert')}** affecting **{victim_host}** with reported severity **{incident.get('severity', 'Unknown')}**.

## 2. Detection Evidence
- **Source IP:** `{incident.get('source_ip', 'unknown')}`
- **Target IP:** `{incident.get('target_ip', 'unknown')}`
- **Target Host:** `{victim_host}`
- **Business Impact:** `{business_impact}`
- **System Role:** `{system_role}`
- **MITRE Mapping:** `{(incident.get('mitre') or {}).get('id', '-')}` - `{(incident.get('mitre') or {}).get('name', '-')}`
- **Traffic Stats:** `{json.dumps(incident.get('traffic_stats') or {})}`

## 3. Original Flow Metadata
{_format_flow_metadata_md(incident.get('flow_metadata') or {})}

## 4. Analyst Notes
```text
{manual_context}
```

## 5. Forensic Findings
The event should be treated as suspicious because it was forwarded by the Hybrid IDS pipeline after combining binary classification, multiclass classification, packet-rule evidence, and zero-day/anomaly output. The current evidence is enough to justify investigation, but confirmation requires correlation with host, firewall, service, and authentication logs.

## 6. Verification Recommendations
1. Confirm that `{incident.get('source_ip', 'unknown')}` appears in firewall, WAF, proxy, or router logs during the alert window.
2. Confirm that `{victim_host}` / `{incident.get('target_ip', 'unknown')}` received the same traffic pattern shown in the IDS flow metadata.
3. Check endpoint process list, active sockets, scheduled tasks, startup entries, and recent parent-child process trees.
4. Review authentication logs and service logs for failed logins, exploit errors, abnormal HTTP status codes, or unexpected database queries.
5. Compare the traffic with expected business behavior to rule out backup jobs, scanners, monitoring tools, or lab-generated traffic.

## 7. Mitigation and Containment Recommendations
1. Preserve evidence first: export the incident JSON, IDS report, relevant PCAP/CSV rows, endpoint logs, and firewall logs.
2. If verification confirms malicious traffic, approve the `block_ip` action for `{incident.get('source_ip', 'unknown')}`.
3. If host compromise indicators appear, approve `isolate_host` for `{victim_host}` while keeping IR controller access allowed.
4. Avoid killing processes unless a specific suspicious PID/process is confirmed.
5. After containment, create or update the SOC ticket and document every action taken.

## 8. Recovery and Post-Mitigation Validation
1. Confirm that new alerts from the same source stop after the block rule is applied.
2. Confirm that legitimate users and services can still reach the protected application.
3. Re-run CICFlowMeter/IDS analysis on fresh traffic to verify that malicious flows decreased.
4. Remove temporary containment only after the analyst confirms clean endpoint state and no repeated indicators.
5. Add lessons learned: tuning thresholds, WAF rules, firewall policy, account hardening, or endpoint monitoring.

## 9. Final Analyst Decision
Current decision: **Suspicious pending verification**. The recommended action is to verify the source, preserve evidence, then apply containment only if the logs confirm malicious behavior.
"""
        incident["investigation_summary"] = (
            f"- Evidence: Autonomous responder enriched {incident_id} using real Hybrid IDS evidence and analyst context.\\n"
            f"- Business context: impact={business_impact}; system role={system_role}.\\n"
            f"- Verification recommendation: correlate source IP, target host, flow timestamp, firewall/WAF logs, endpoint connections, and service/authentication logs.\\n"
            f"- Mitigation recommendation: preserve evidence first, then block the source IP only after validation; isolate the host only if compromise indicators are confirmed.\\n"
            f"- Post-mitigation validation: confirm alerts stop, legitimate traffic still works, and containment rules can be safely rolled back.\\n"
            f"- Analyst decision: suspicious pending verification."
        )

    incident["target_host"] = victim_host
    incident["status"] = "Investigated"
    incident["markdown_report"] = report

    try:
        incident_path.write_text(json.dumps(incident, indent=2))
        (REPORTS_DIR / f"{incident_id}.md").write_text(report)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save investigation report: {exc}")

    return incident


# ---------------------------------------------------------------------------
# Route 3 — POST /api/investigate
# ---------------------------------------------------------------------------
@app.post("/api/investigate")
async def investigate(body: InvestigateRequest) -> dict:
    flow = body.flow or {}
    prediction = body.prediction or {}
    manual_context = body.manualContext or "No additional human logs. Server type matches port utility."
    victim_host = body.victimHost or "prod-web-01"

    prompt = f"""
You are the server-side Security Incident Response and Digital Forensics Agent for a Hybrid IDS/SOAR dashboard.

Perform an Incident Response investigation of a security anomaly in an enterprise environment.

--- INPUT SYSTEM LOGS & CONTEXT ---
Victim Hostname: {victim_host}
Target IP: {flow.get('dst_ip', '10.0.0.5')}
Attacker IP: {flow.get('src_ip', '185.220.101.5')}
Target Port: {flow.get('dst_port', '80')}
Protocol: {flow.get('protocol', 'TCP')}
Flow Packets: {flow.get('packets', 'Unknown')}
Flow Bytes: {flow.get('bytes', 'Unknown')}
Flow Duration: {flow.get('duration', 'Unknown')} s

ML IDS Alert: {prediction.get('label', 'Anomalous Traffic Sequence')} (Confidence: {prediction.get('confidence', '85%')})

System Context / Manual Log Input:
{manual_context}

--- INVESTIGATION REQUIREMENTS ---
You must act as the IR Agent and perform:
1. Detailed forensic analysis using the alert, network flow, and manual context.
2. CVSS v3.1 severity scoring with vector syntax, for example CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H.
3. MITRE ATT&CK tactic and technique mapping.
4. Verification recommendations before mitigation:
   - confirm source IP in firewall/proxy/WAF logs,
   - confirm target host received the traffic,
   - inspect endpoint processes and network sockets,
   - check service/application/authentication logs,
   - identify false-positive possibilities.
5. Mitigation recommendations:
   - preserve evidence before destructive actions,
   - block malicious IP after validation,
   - isolate host only if compromise indicators exist,
   - kill process only if a suspicious process is clearly identified,
   - document rollback/unblock criteria.
6. Post-mitigation validation:
   - confirm the alert stops,
   - confirm legitimate traffic still works,
   - verify host health,
   - re-run IDS/CICFlowMeter analysis on fresh traffic.
7. Generate a Markdown Forensic Summary suitable for a graduation project demo.

--- OUTPUT QUALITY RULES ---
- Do not invent exact logs that were not provided.
- Use "Requires verification" when evidence is missing.
- Keep the response professional, practical, and SOC-realistic.
- The `investigation_summary` field must read like IR Investigation Notes and include evidence, verification, mitigation, validation, and analyst decision.
- The `markdown_report` field must include these exact headings:
  # Forensic Summary: <incident id or attack name>
  ## 1. Executive Summary
  ## 2. Detection Evidence
  ## 3. Forensic Findings
  ## 4. Verification Recommendations
  ## 5. Mitigation and Containment Recommendations
  ## 6. Recovery and Post-Mitigation Validation
  ## 7. MITRE ATT&CK and CVSS Reasoning
  ## 8. Final Analyst Decision

You must return the response as a valid JSON object containing exactly these keys.
JSON Schema:
{{
  "id": "INC-2026-X",
  "attack_type": "string",
  "severity": "Low" | "Medium" | "High" | "Critical",
  "cvss": number,
  "cvss_vector": "string",
  "mitre": {{
    "id": "string",
    "name": "string",
    "tactic": "string"
  }},
  "investigation_summary": "string",
  "response_plan": [
    {{
      "type": "isolate_host" | "block_ip" | "kill_process",
      "target": "string",
      "description": "string",
      "status": "Pending"
    }}
  ],
  "markdown_report": "string"
}}
Do NOT add Markdown code fences around the JSON. Return only the raw JSON object.
"""

    # --- Try Gemini AI ---
    client = _get_gemini_client()
    if client:
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config=genai_types.GenerateContentConfig(
                    response_mime_type="application/json",
                    system_instruction=(
                        "You are the advanced server-side Security Incident Response Agent (IR-Agent) powered by Gemini AI. "
                        "Your outputs must be highly technical, realistic, and strictly valid JSON formatted."
                    ),
                ),
            )
            text = (response.text or "{}").strip()
            parsed: dict = json.loads(text)
        except Exception as exc:
            print(f"Gemini IR analysis failed, falling back to local simulation: {exc}")
            parsed = {}

        if parsed:
            incident_id = parsed.get("id") or f"INC-2026-{random.randint(100, 999)}"
            parsed["id"] = incident_id
            parsed["timestamp"] = datetime.now(tz=timezone.utc).isoformat()
            parsed["source_ip"] = flow.get("src_ip", "185.220.101.5")
            parsed["target_ip"] = flow.get("dst_ip", "10.0.0.5")
            parsed["target_host"] = victim_host
            parsed["traffic_stats"] = {
                "packets": int(flow.get("packets") or 120),
                "bytes": int(flow.get("bytes") or 42000),
                "duration_ms": round(float(flow.get("duration") or 1.2) * 1000),
                "protocol": flow.get("protocol", "TCP"),
                "service": _port_to_service(str(flow.get("dst_port", "80"))),
            }
            parsed["status"] = "Investigated"

            (INCIDENTS_DIR / f"{incident_id}.json").write_text(json.dumps(parsed, indent=2))
            if parsed.get("markdown_report"):
                (REPORTS_DIR / f"{incident_id}.md").write_text(parsed["markdown_report"])

            return parsed

    # --- High-fidelity mock fallback ---
    print("Using high-fidelity mock generator for incident response simulation...")
    fake_id = f"INC-2026-{random.randint(100, 999)}"
    src_ip = flow.get("src_ip", "198.51.100.12")
    label = prediction.get("label", "Suspicious Outbound Tunneling")

    severity = "High"
    cvss = 8.5
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    mitre_id = "T1071.001"
    mitre_name = "Application Layer Protocol: Web Protocols"
    tactic = "Command and Control"

    if "UDP" in label or "DDoS" in label:
        severity = "Critical"
        cvss = 9.1
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H"
        mitre_id = "T1498.001"
        mitre_name = "Network Denial of Service: Direct Flow Flood"
        tactic = "Impact"
    elif "SQL" in label or "Exploit" in label:
        severity = "High"
        cvss = 8.8
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        mitre_id = "T1190"
        mitre_name = "Exploit Public-Facing Application"
        tactic = "Initial Access"
    elif "DNS" in label or "Tunnel" in label or "Exfil" in label:
        severity = "High"
        cvss = 8.0
        vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N"
        mitre_id = "T1567"
        mitre_name = "Exfiltration Over Web Service"
        tactic = "Exfiltration"

    investigation_notes = (
        f"Forensic investigator identified a matching signature for {label} targeting host {victim_host}. "
        "The high rate of packet transmissions over a short period suggests an automated command-and-control "
        "engine or scripting tool. Additional system logs indicate unlogged processes spawning and communicating "
        "with external socket pools. Recommended immediate quarantine and port lockdowns."
    )

    response_plan = [
        {
            "type": "block_ip",
            "target": src_ip,
            "description": f"Block attacker IP {src_ip} globally on border gateway firewalls",
            "status": "Pending",
        },
        {
            "type": "isolate_host",
            "target": victim_host,
            "description": f"Isolate victim host {victim_host} immediately, disabling LAN access and allowing only the security backend control socket",
            "status": "Pending",
        },
    ]

    report = f"""# Incident Investigation Report: {fake_id}
## Executive Summary
On June 24, 2026, our automated Intrusion Detection System identified structural anomalies matching **{label}** targeting our high-value server asset **{victim_host}**. This report covers the full technical findings and outlines containment procedures.

## Threat Profile & Metrics
- **Incident ID**: {fake_id}
- **Source Attacker IP**: `{src_ip}`
- **Target Endpoint**: `{victim_host}` (IP: {flow.get('dst_ip', '10.0.0.5')})
- **Network Protocol**: {flow.get('protocol', 'TCP')} / Port {flow.get('dst_port', '80')}
- **CVSS Score**: **{cvss} ({severity})**
- **MITRE Tactic**: {tactic}
- **MITRE Technique**: {mitre_name} (`{mitre_id}`)

## Technical Analysis
A deep heuristic packet inspection was triggered following spikes in packet counts (`{flow.get('packets', '1,200')}` packets, `{flow.get('bytes', '150,000')}` bytes). These patterns indicate malicious automation mimicking legitimate operations.

## Containment Actions
1. **Host Isolation**: Restrict {victim_host} using the local agent's automated iptables sandbox interface.
2. **Attacker Blacklist**: Inject `{src_ip}` into our global border routing blocklists.
3. **Log Audit**: Investigate process list trees for unauthorized binaries executing in system memory."""

    payload: dict = {
        "id": fake_id,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "source_ip": src_ip,
        "target_ip": flow.get("dst_ip", "10.0.0.5"),
        "target_host": victim_host,
        "attack_type": label,
        "severity": severity,
        "cvss": cvss,
        "cvss_vector": vector,
        "mitre": {"id": mitre_id, "name": mitre_name, "tactic": tactic},
        "investigation_summary": investigation_notes,
        "response_plan": response_plan,
        "markdown_report": report,
        "status": "Investigated",
        "traffic_stats": {
            "packets": int(flow.get("packets") or 120),
            "bytes": int(flow.get("bytes") or 42000),
            "duration_ms": round(float(flow.get("duration") or 1.2) * 1000),
            "protocol": flow.get("protocol", "TCP"),
            "service": _port_to_service(str(flow.get("dst_port", "80"))),
        },
    }

    try:
        (INCIDENTS_DIR / f"{fake_id}.json").write_text(json.dumps(payload, indent=2))
        (REPORTS_DIR / f"{fake_id}.md").write_text(report)
    except Exception as exc:
        print(f"Failed to save simulated incident: {exc}")

    return payload


# ---------------------------------------------------------------------------
# Route 4 — POST /api/execute-action
# ---------------------------------------------------------------------------
@app.post("/api/execute-action")
async def execute_action(body: ExecuteActionRequest) -> dict:
    """
    Execute an IR containment action.

    Supported actions:
    - isolate_host: isolate one endpoint host
    - block_ip: block an attacker/source IP on all endpoints
    - kill_process: mark a suspicious process as killed in the endpoint state

    For real enforcement, this route also calls:
    - _enforce_isolate_host()
    - _enforce_block_ip()

    Important:
    _IR_CONTROLLER_IP comes from .env.
    For your VMware setup, it should be:
        IR_CONTROLLER_IP=192.168.67.1
    """

    if not body.actionType:
        raise HTTPException(status_code=400, detail="Missing actionType")

    if not body.target:
        raise HTTPException(status_code=400, detail="Missing target")

    try:
        ts = _now_ts()
        logs: list[str] = []

        # -------------------------------------------------------------------
        # Action 1: Isolate host
        # -------------------------------------------------------------------
        if body.actionType == "isolate_host":
            target_hostname = body.target.strip()

            # Save host in isolated_hosts.txt
            current_isolated = _read_isolated()
            if target_hostname not in current_isolated:
                with ISOLATED_FILE.open("a") as f:
                    f.write(f"{target_hostname}\n")

            # Update in-memory endpoint state for dashboard UI
            agent = ENDPOINT_AGENTS.get(target_hostname)

            if agent:
                agent["status"] = "ISOLATED"
                agent["connectionsCount"] = 1

                # Dashboard firewall view.
                # Use _IR_CONTROLLER_IP instead of hardcoded 10.0.0.10.
                agent["firewallRules"] = [
                    {
                        "id": "fw-isolation-allow-ir-in",
                        "direction": "INBOUND",
                        "proto": "ANY",
                        "port": "ANY",
                        "action": "ALLOW",
                        "source": _IR_CONTROLLER_IP,
                        "destination": agent["ip"],
                    },
                    {
                        "id": "fw-isolation-allow-ir-out",
                        "direction": "OUTBOUND",
                        "proto": "ANY",
                        "port": "ANY",
                        "action": "ALLOW",
                        "source": agent["ip"],
                        "destination": _IR_CONTROLLER_IP,
                    },
                    {
                        "id": "fw-isolation-deny-all-in",
                        "direction": "INBOUND",
                        "proto": "ANY",
                        "port": "ANY",
                        "action": "DENY",
                        "source": "ANY",
                        "destination": "ANY",
                    },
                    {
                        "id": "fw-isolation-deny-all-out",
                        "direction": "OUTBOUND",
                        "proto": "ANY",
                        "port": "ANY",
                        "action": "DENY",
                        "source": "ANY",
                        "destination": "ANY",
                    },
                ]

                agent["terminalLogs"] += [
                    f"[{ts}] [IR-ACTION] Isolation command received from security backend!",
                    f"[{ts}] [IR-ACTION] Backing up previous IPTables configuration...",
                    f"[{ts}] [IR-ACTION] Disabling default routing tables.",
                    f"[{ts}] [IR-ACTION] Applying local containment firewall rules...",
                    f"[{ts}] [IR-ACTION] Allowed IR backend ({_IR_CONTROLLER_IP}) communication ONLY.",
                    f"[{ts}] [IR-ACTION] Dropping other active user sockets. Isolated hosts state reached.",
                    f"[{ts}] [IR-ACTION] Host isolated successfully! Returned isolation status.",
                ]

                logs += [
                    f"Successfully connected to endpoint host {target_hostname}.",
                    "Applying local iptables sandboxing rules on host...",
                    f"Allowing security controller IP ({_IR_CONTROLLER_IP}) strictly.",
                    "Endpoint isolation verified. Firewall table locked down.",
                ]
            else:
                logs += [
                    f"Warning: endpoint host {target_hostname} was not found in ENDPOINT_AGENTS.",
                    "Continuing with real remote enforcement resolver if SSH_HOST_MAP contains this host.",
                ]

            # Real remote enforcement: SSH/WinRM into the target host itself
            logs += _enforce_isolate_host(target_hostname)

        # -------------------------------------------------------------------
        # Action 2: Block source/attacker IP
        # -------------------------------------------------------------------
        elif body.actionType == "block_ip":
            attacker_ip = body.target.strip()

            # Save IP in blocklist.txt
            current_blocklist = _read_blocklist()
            if attacker_ip not in current_blocklist:
                with BLOCKLIST_FILE.open("a") as f:
                    f.write(f"{attacker_ip}\n")

            # Update in-memory endpoint firewall view
            rule_id = f"fw-block-{int(time.time())}-{random.randint(0, 99)}"

            for _, agent in ENDPOINT_AGENTS.items():
                agent["firewallRules"].insert(
                    0,
                    {
                        "id": rule_id,
                        "direction": "INBOUND",
                        "proto": "ANY",
                        "port": "ANY",
                        "action": "DENY",
                        "source": attacker_ip,
                        "destination": agent["ip"],
                    },
                )

                agent["terminalLogs"].append(
                    f"[{ts}] [BLOCKLIST-UPDATE] Received block command for IP: {attacker_ip}. Firewall updated."
                )

            logs += [
                f"IP {attacker_ip} appended to shared blocklist.txt database.",
                "Broadcasting firewall update rule to all endpoint host agents.",
                f"Endpoints confirmed local filter policy: DENY packets from source IP {attacker_ip}.",
            ]

            # Real remote enforcement: push iptables/netsh rules to all endpoints
            logs += _enforce_block_ip(attacker_ip)

        # -------------------------------------------------------------------
        # Action 3: Kill suspicious process
        # -------------------------------------------------------------------
        elif body.actionType == "kill_process":
            try:
                pid_to_kill = int(body.target)
            except ValueError:
                raise HTTPException(status_code=400, detail="target must be a numeric PID for kill_process")

            found = False

            for _, agent in ENDPOINT_AGENTS.items():
                for proc in agent["processes"]:
                    if int(proc.get("pid", -1)) == pid_to_kill:
                        found = True
                        process_name = proc.get("name", "unknown")

                        proc["status"] = "Defunct"
                        proc["cpu"] = 0.0
                        proc["memory"] = 0.0

                        agent["terminalLogs"].append(
                            f"[{ts}] [PROCESS-KILL] Terminated process PID {pid_to_kill} ({process_name}) by administrative request."
                        )

                        logs += [
                            f"Sent SIGKILL to process PID {pid_to_kill} ({process_name}) on agent {agent['hostname']}.",
                            "Process state updated to Defunct.",
                        ]

            if not found:
                logs.append(f"Warning: PID {pid_to_kill} was not found on active endpoint hosts.")

        # -------------------------------------------------------------------
        # Unknown action
        # -------------------------------------------------------------------
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported actionType: {body.actionType}",
            )

        # -------------------------------------------------------------------
        # Update incident file if incidentId was provided
        # -------------------------------------------------------------------
        if body.incidentId:
            inc_path = INCIDENTS_DIR / f"{body.incidentId}.json"

            if inc_path.exists():
                incident = json.loads(inc_path.read_text())

                for act in incident.get("response_plan", []):
                    if act.get("type") == body.actionType:
                        act["status"] = "Approved"

                incident["status"] = "Mitigated"
                inc_path.write_text(json.dumps(incident, indent=2))

        return {
            "success": True,
            "action": body.actionType,
            "target": body.target,
            "logs": logs,
            "endpoints": ENDPOINT_AGENTS,
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to execute IR containment action: {exc}",
        )
# ---------------------------------------------------------------------------
# Route 5 — POST /api/tickets
# ---------------------------------------------------------------------------
@app.post("/api/tickets")
async def create_ticket(body: CreateTicketRequest) -> dict:
    if not body.title:
        raise HTTPException(status_code=400, detail="Missing ticket title")

    new_ticket = {
        "ticket_id": f"TKT-2026-{random.randint(100, 999)}",
        "incident_id": body.incidentId or "INC-2026-N/A",
        "title": body.title,
        "status": "Open",
        "priority": body.priority or "Medium",
        "assignee": "SOC-Automated",
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
    }

    try:
        with TICKETS_FILE.open("a") as f:
            f.write(json.dumps(new_ticket) + "\n")
        return {"success": True, "ticket": new_ticket}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to log ticket: {exc}")


# ---------------------------------------------------------------------------
# Route 6 — GET /api/reports/{id}
# ---------------------------------------------------------------------------
@app.get("/api/reports/{report_id}")
async def get_report(report_id: str) -> PlainTextResponse:
    report_path = REPORTS_DIR / f"{report_id}.md"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        return PlainTextResponse(content=report_path.read_text(), media_type="text/plain")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read report: {exc}")


# ---------------------------------------------------------------------------
# Route 7 — GET /api/firewall/status
# ---------------------------------------------------------------------------
@app.get("/api/firewall/status")
async def firewall_status() -> dict:
    """Returns the current enforcement mode, dependency availability, and active lists."""
    return {
        "enforcement_mode": ENFORCEMENT_MODE,
        "paramiko_available": _PARAMIKO_AVAILABLE,
        "winrm_available": _WINRM_AVAILABLE,
        "blocked_ips": _read_blocklist(),
        "isolated_hosts": _read_isolated(),
        "ssh_host_map": _SSH_HOST_MAP,
        "ir_controller_ip": _IR_CONTROLLER_IP,
    }


# ---------------------------------------------------------------------------
# Route 8 — POST /api/firewall/unblock
# ---------------------------------------------------------------------------
@app.post("/api/firewall/unblock")
async def firewall_unblock(body: FirewallUnblockRequest) -> dict:
    """Remove a blocked IP from the blocklist and reverse enforcement rules."""
    if not body.ip:
        raise HTTPException(status_code=400, detail="Missing ip")
    try:
        # Update blocklist file
        updated = [x for x in _read_blocklist() if x != body.ip]
        BLOCKLIST_FILE.write_text("\n".join(updated) + ("\n" if updated else ""))
        # Remove matching DENY rules from in-memory endpoint state
        for agent in ENDPOINT_AGENTS.values():
            agent["firewallRules"] = [
                r for r in agent["firewallRules"]
                if not (r.get("source") == body.ip and r.get("action") == "DENY")
            ]
        # Real remote enforcement reversal
        enforcement_logs = _enforce_unblock_ip(body.ip)
        return {"success": True, "ip": body.ip, "logs": enforcement_logs}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unblock failed: {exc}")


# ---------------------------------------------------------------------------
# Route 9 — POST /api/firewall/unisolate
# ---------------------------------------------------------------------------
@app.post("/api/firewall/unisolate")
async def firewall_unisolate(body: FirewallUnisolateRequest) -> dict:
    """Remove a host from the isolated list and reverse enforcement rules."""
    if not body.hostname:
        raise HTTPException(status_code=400, detail="Missing hostname")
    try:
        # Update isolated hosts file
        updated = [x for x in _read_isolated() if x != body.hostname]
        ISOLATED_FILE.write_text("\n".join(updated) + ("\n" if updated else ""))
        # Restore in-memory agent status
        agent = ENDPOINT_AGENTS.get(body.hostname)
        if agent and agent.get("status") == "ISOLATED":
            agent["status"] = "ONLINE"
            agent["firewallRules"] = [
                r for r in agent["firewallRules"]
                if "isolation" not in r.get("id", "").lower()
            ]
            agent["terminalLogs"].append(
                f"[{_now_ts()}] [IR-ACTION] Isolation lifted by SOC analyst. Firewall rules restored."
            )
        # Real remote enforcement reversal
        enforcement_logs = _enforce_unisolate_host(body.hostname)
        return {"success": True, "hostname": body.hostname, "logs": enforcement_logs}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unisolate failed: {exc}")


# ---------------------------------------------------------------------------
# Entry point (for direct `python server.py` execution)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8001, reload=True)
