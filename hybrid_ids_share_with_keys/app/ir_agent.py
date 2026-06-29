"""
Incident Response helper for the Hybrid IDS project.

This file does two things:
1. Builds a safe deterministic IR plan from the IDS/ML analysis output.
2. Optionally calls OpenRouter to generate an analyst-style Markdown report.

The containment commands are DRY-RUN recommendations only. They are returned as text
so the dashboard can show them without executing anything on the machine.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any

import requests
from fastapi import HTTPException


OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-20b:free")


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except Exception:
        return default


def _normalize_label(value: Any) -> str:
    return str(value or "").strip()


def extract_suspicious_ips(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract suspicious source IPs from packet-rule output and flow details."""
    counts: Counter[str] = Counter()
    evidence: dict[str, set[str]] = {}

    def add_ip(ip: Any, reason: str, count: int = 1) -> None:
        ip_text = str(ip or "").strip()
        if not ip_text or ip_text in {"-", "None", "nan"}:
            return
        counts[ip_text] += max(1, int(count))
        evidence.setdefault(ip_text, set()).add(reason)

    rule_result = analysis.get("rule_result", {}) or {}
    rule_summary = rule_result.get("summary", {}) if isinstance(rule_result, dict) else {}

    for item in rule_summary.get("top_sources", []) or []:
        add_ip(item.get("src"), "packet rule top source", _to_int(item.get("count"), 1))

    for alert in rule_result.get("sample_alerts", []) or []:
        add_ip(alert.get("src") or alert.get("source_ip") or alert.get("Source IP"), "sample packet alert", 1)

    for row in analysis.get("results", []) or []:
        add_ip(
            row.get("src")
            or row.get("source_ip")
            or row.get("Src IP")
            or row.get("Source IP"),
            "AI detailed prediction row",
            1,
        )

    for row in analysis.get("zero_day_details", []) or []:
        if str(row.get("zero_day_prediction", "")).upper() == "POSSIBLE_ZERO_DAY" or row.get("above_threshold") is True:
            add_ip(
                row.get("source_ip")
                or row.get("src")
                or row.get("Src IP")
                or row.get("Source IP"),
                "zero-day anomaly row",
                1,
            )

    output = []
    for ip, count in counts.most_common(10):
        output.append(
            {
                "ip": ip,
                "alert_count": int(count),
                "evidence": sorted(evidence.get(ip, [])),
            }
        )
    return output


def _dominant_attack(analysis: dict[str, Any]) -> str:
    attack_summary = analysis.get("attack_type_summary", {}) or {}
    packet_summary = ((analysis.get("rule_result", {}) or {}).get("summary", {}) or {}).get("attack_type_summary", {}) or {}

    merged: Counter[str] = Counter()
    for source in [attack_summary, packet_summary]:
        if isinstance(source, dict):
            for key, value in source.items():
                merged[str(key)] += _to_int(value, 0)

    zero_day_summary = analysis.get("zero_day_summary", {}) or {}
    if str(zero_day_summary.get("decision", "")).upper() == "POSSIBLE_ZERO_DAY":
        merged["possible_zero_day"] += _to_int(zero_day_summary.get("anomalous_rows", 1), 1)

    non_zero = {k: v for k, v in merged.items() if v > 0}
    if not non_zero:
        return "Unknown"
    return max(non_zero, key=non_zero.get)


def calculate_severity(analysis: dict[str, Any], analyst_context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Calculate a clear severity score that can be explained in the dashboard."""
    analyst_context = analyst_context or {}
    reasons: list[str] = []
    score = 0

    decision = _normalize_label(analysis.get("official_binary_decision", "UNKNOWN"))
    decision_l = decision.lower()
    attack_rate = _to_float(analysis.get("attack_rate", 0.0))
    attack_count = _to_int(analysis.get("attack_count", 0))

    binary_summary = analysis.get("binary_summary", {}) or {}
    xgb_count = _to_int(binary_summary.get("xgb_count", 0))
    lstm_count = _to_int(binary_summary.get("lstm_count", 0))
    xgb_mean = _to_float(binary_summary.get("xgb_mean", 0.0))
    lstm_mean = _to_float(binary_summary.get("lstm_mean", 0.0))

    rule_result = analysis.get("rule_result", {}) or {}
    packet_summary = rule_result.get("summary", {}) if isinstance(rule_result, dict) else {}
    packet_alerts = _to_int(packet_summary.get("total_alerts", 0))

    zero_day_summary = analysis.get("zero_day_summary", {}) or {}
    zero_day_decision = str(zero_day_summary.get("decision", "")).upper()
    zero_day_rows = _to_int(zero_day_summary.get("anomalous_rows", 0))
    zero_day_rate = _to_float(zero_day_summary.get("anomaly_rate_percent", 0.0))
    zero_day_status = str(zero_day_summary.get("status", "")).lower()

    if "attack" in decision_l:
        score += 30
        reasons.append("Binary IDS decision indicates attack.")
    elif "suspicious" in decision_l or "single model" in decision_l:
        score += 18
        reasons.append("At least one binary model flagged suspicious traffic.")
    elif "benign" in decision_l:
        reasons.append("Binary IDS decision is benign.")

    if attack_count > 0:
        score += min(20, 5 + attack_count)
        reasons.append(f"AI pipeline flagged {attack_count} malicious/suspicious flows.")

    if attack_rate >= 50:
        score += 20
        reasons.append(f"High attack rate detected: {attack_rate:.2f}%.")
    elif attack_rate >= 10:
        score += 12
        reasons.append(f"Moderate attack rate detected: {attack_rate:.2f}%.")
    elif attack_rate > 0:
        score += 6
        reasons.append(f"Low but non-zero attack rate detected: {attack_rate:.2f}%.")

    if xgb_count > 0 and lstm_count > 0:
        score += 15
        reasons.append("Both XGBoost and LSTM produced malicious detections.")
    elif xgb_count > 0 or lstm_count > 0:
        score += 8
        reasons.append("One AI model produced malicious detections.")

    if max(xgb_mean, lstm_mean) >= 0.90:
        score += 8
        reasons.append("A model confidence mean is very high.")
    elif max(xgb_mean, lstm_mean) >= 0.70:
        score += 4
        reasons.append("A model confidence mean is elevated.")

    if packet_alerts >= 100:
        score += 18
        reasons.append(f"Packet rules produced a large number of alerts: {packet_alerts}.")
    elif packet_alerts >= 10:
        score += 12
        reasons.append(f"Packet rules produced multiple alerts: {packet_alerts}.")
    elif packet_alerts > 0:
        score += 6
        reasons.append(f"Packet rules produced alerts: {packet_alerts}.")

    dominant_attack = _dominant_attack(analysis).lower()
    if any(word in dominant_attack for word in ["sql", "infiltration", "botnet", "brute", "web"]):
        score += 10
        reasons.append(f"Dominant attack family may have high impact: {_dominant_attack(analysis)}.")
    elif any(word in dominant_attack for word in ["dos", "ddos", "port"]):
        score += 6
        reasons.append(f"Dominant attack family affects availability/reconnaissance: {_dominant_attack(analysis)}.")

    if zero_day_decision == "POSSIBLE_ZERO_DAY":
        score += 22
        reasons.append(f"Zero-day autoencoder detected anomalous unknown traffic in {zero_day_rows} rows ({zero_day_rate:.2f}%).")
    elif zero_day_status == "ok" and zero_day_decision == "NORMAL":
        reasons.append("Zero-day autoencoder did not detect unknown anomalous behavior.")
    elif zero_day_status in {"not_available", "error"}:
        reasons.append("Zero-day autoencoder was not available or could not run, so severity is based on other evidence.")

    criticality = str(
        analyst_context.get("asset_criticality")
        or analyst_context.get("criticality")
        or analyst_context.get("asset_context", {}).get("criticality", "")
    ).lower()
    if criticality == "critical":
        score += 15
        reasons.append("Analyst context marks the asset as Critical.")
    elif criticality == "high":
        score += 10
        reasons.append("Analyst context marks the asset as High criticality.")
    elif criticality == "medium":
        score += 5
        reasons.append("Analyst context marks the asset as Medium criticality.")

    hint = str(analyst_context.get("analyst_severity_hint", "")).lower()
    if hint == "critical":
        score += 8
        reasons.append("Analyst severity hint is Critical.")
    elif hint == "high":
        score += 5
        reasons.append("Analyst severity hint is High.")

    score = max(0, min(100, int(score)))

    if score >= 80:
        label = "Critical"
    elif score >= 60:
        label = "High"
    elif score >= 35:
        label = "Medium"
    elif score > 0:
        label = "Low"
    else:
        label = "Informational"

    return {
        "score": score,
        "label": label,
        "dominant_attack": _dominant_attack(analysis),
        "reasons": reasons,
    }


def _build_commands_for_ip(ip: str) -> list[dict[str, str]]:
    return [
        {
            "platform": "Windows Defender Firewall",
            "purpose": "Block suspicious source IP inbound",
            "command": f'netsh advfirewall firewall add rule name="HybridIDS Block {ip}" dir=in action=block remoteip={ip}',
        },
        {
            "platform": "Linux iptables",
            "purpose": "Drop traffic from suspicious source IP",
            "command": f"sudo iptables -A INPUT -s {ip} -j DROP",
        },
        {
            "platform": "Linux ufw",
            "purpose": "Deny traffic from suspicious source IP",
            "command": f"sudo ufw deny from {ip}",
        },
        {
            "platform": "Firewall / Router template",
            "purpose": "Block at network edge",
            "command": f"deny ip host {ip} any  # apply on firewall ACL after validation",
        },
    ]


def build_incident_response(
    analysis: dict[str, Any],
    analyst_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic safe IR result from the actual IDS output."""
    analyst_context = analyst_context or {}
    severity = calculate_severity(analysis, analyst_context)
    suspicious_ips = extract_suspicious_ips(analysis)

    decision = _normalize_label(analysis.get("official_binary_decision", "UNKNOWN"))
    flows = _to_int(analysis.get("flows_analyzed", 0))
    attack_count = _to_int(analysis.get("attack_count", 0))
    packet_alerts = _to_int(((analysis.get("rule_result", {}) or {}).get("summary", {}) or {}).get("total_alerts", 0))

    recommended_actions = []
    if severity["label"] in ["Critical", "High"]:
        recommended_actions.extend(
            [
                "Escalate to SOC/IR lead and open an incident ticket.",
                "Validate the top suspicious source IPs using firewall, IDS, server, and authentication logs.",
                "Block confirmed malicious source IPs at the firewall or endpoint firewall.",
                "Check whether the destination host shows signs of compromise.",
            ]
        )
    elif severity["label"] == "Medium":
        recommended_actions.extend(
            [
                "Investigate the event before blocking automatically.",
                "Correlate with logs from the target host and perimeter firewall.",
                "Increase monitoring for the suspicious IPs and destination service.",
            ]
        )
    else:
        recommended_actions.extend(
            [
                "Keep the alert for monitoring and correlation.",
                "No containment action is recommended unless more evidence appears.",
            ]
        )

    zero_day_summary = analysis.get("zero_day_summary", {}) or {}
    if str(zero_day_summary.get("decision", "")).upper() == "POSSIBLE_ZERO_DAY":
        recommended_actions.insert(0, "Treat this as a possible unknown/zero-day anomaly until validated by logs and packet evidence.")
        recommended_actions.append("Preserve the PCAP/CSV sample and reconstruction-error evidence for offline analysis and model tuning.")

    verification_steps = [
        "Confirm whether the suspicious source IP communicated repeatedly with the same destination.",
        "Check destination service logs for failed logins, abnormal requests, errors, or crashes.",
        "Compare the timestamp with firewall, endpoint, and application logs.",
        "Verify whether the traffic is expected business traffic or a known scanner/test host.",
        "If the destination is critical, capture volatile evidence before containment.",
    ]

    commands = []
    for item in suspicious_ips[:5]:
        commands.extend(_build_commands_for_ip(item["ip"]))

    isolate_host_commands = [
        {
            "platform": "Windows host - emergency local isolation",
            "purpose": "Block inbound and outbound traffic on the affected host after approval",
            "command": "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound",
        },
        {
            "platform": "Linux host - emergency local isolation",
            "purpose": "Drop inbound and outbound traffic on the affected host after approval",
            "command": "sudo iptables -P INPUT DROP && sudo iptables -P OUTPUT DROP && sudo iptables -P FORWARD DROP",
        },
        {
            "platform": "Network switch / NAC template",
            "purpose": "Move affected endpoint to quarantine VLAN",
            "command": "Move endpoint switch port to quarantine VLAN / isolate via EDR or NAC console",
        },
    ]

    return {
        "mode": "dry_run_recommendations_only",
        "summary": {
            "decision": decision,
            "flows_analyzed": flows,
            "attack_count": attack_count,
            "packet_rule_alerts": packet_alerts,
            "zero_day_decision": (analysis.get("zero_day_summary", {}) or {}).get("decision", "UNAVAILABLE"),
            "dominant_attack": severity["dominant_attack"],
        },
        "severity": severity,
        "suspicious_ips": suspicious_ips,
        "verification_steps": verification_steps,
        "recommended_actions": recommended_actions,
        "block_ip_commands": commands,
        "isolate_host_commands": isolate_host_commands,
        "safety_note": "Commands are generated as dry-run recommendations. The application does not execute containment actions automatically.",
    }


def build_llm_triage_prompt(
    analysis_result: dict[str, Any],
    analyst_context: dict[str, Any] | None = None,
    asset_context: dict[str, Any] | None = None,
) -> str:
    analyst_context = analyst_context or {}
    asset_context = asset_context or {}
    deterministic_ir = build_incident_response(analysis_result, analyst_context)

    compact_analysis = {
        "filename": analysis_result.get("filename"),
        "official_binary_decision": analysis_result.get("official_binary_decision"),
        "flows_analyzed": analysis_result.get("flows_analyzed"),
        "attack_count": analysis_result.get("attack_count"),
        "attack_rate": analysis_result.get("attack_rate"),
        "binary_summary": analysis_result.get("binary_summary"),
        "multiclass_summary": analysis_result.get("multiclass_summary"),
        "attack_type_summary": analysis_result.get("attack_type_summary"),
        "packet_rule_summary": (analysis_result.get("rule_result", {}) or {}).get("summary", {}),
        "sample_packet_alerts": (analysis_result.get("rule_result", {}) or {}).get("sample_alerts", [])[:10],
        "zero_day_summary": analysis_result.get("zero_day_summary", {}),
        "zero_day_top_anomalies": analysis_result.get("zero_day_details", [])[:10],
        "deterministic_incident_response": deterministic_ir,
    }

    return (
        "You are an Incident Response Assistant for a graduation project called Hybrid IDS powered by AI.\n"
        "The IDS has rule-based packet detections, binary ML detection, and conditional multiclass attack classification.\n\n"
        "Use only the evidence in the JSON. Do not invent logs or confirmed compromise.\n"
        "Return a practical SOC-style report with these exact Markdown sections:\n\n"
        "## Calculated Severity\n"
        "## Evidence From IDS and AI Models\n"
        "## Analyst and Asset Context Impact\n"
        "## Investigation Steps\n"
        "## Recommended Containment\n"
        "## Dry-Run Mitigation Commands\n"
        "## Notes and Limitations\n\n"
        "Important: mitigation commands must be defensive and must be presented as dry-run / approval-required actions.\n\n"
        "Hybrid IDS Analysis JSON:\n"
        "```json\n"
        f"{json.dumps(compact_analysis, indent=2, default=str)}\n"
        "```\n\n"
        "Analyst Context JSON:\n"
        "```json\n"
        f"{json.dumps(analyst_context, indent=2, default=str)}\n"
        "```\n\n"
        "Asset Context JSON:\n"
        "```json\n"
        f"{json.dumps(asset_context, indent=2, default=str)}\n"
        "```"
    )


def call_openrouter_triage(
    analysis_result: dict[str, Any],
    analyst_context: dict[str, Any] | None = None,
    asset_context: dict[str, Any] | None = None,
) -> str:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="OPENROUTER_API_KEY is not set.")

    payload = {
        "model": OPENROUTER_MODEL,
        "temperature": 0.2,
        "max_tokens": 1400,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a defensive Incident Response assistant. "
                    "You help SOC analysts explain IDS/ML alerts, severity, investigation steps, and safe containment."
                ),
            },
            {
                "role": "user",
                "content": build_llm_triage_prompt(analysis_result, analyst_context, asset_context),
            },
        ],
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:8501",
        "X-OpenRouter-Title": "Hybrid IDS Incident Response",
    }

    try:
        response = requests.post(
            OPENROUTER_API_URL,
            headers=headers,
            json=payload,
            timeout=45,
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]
    except requests.exceptions.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"OpenRouter request failed: {exc}")
    except (KeyError, IndexError, TypeError) as exc:
        raise HTTPException(status_code=502, detail=f"Unexpected OpenRouter response format: {exc}")


# ---------------------------------------------------------------------------
# Lightweight IR state store adapted from the uploaded incident-response app.
# This keeps the graduation project safe: actions update local demo files only.
# ---------------------------------------------------------------------------
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
INCIDENTS_DIR = DATA_DIR / "incidents"
REPORTS_DIR = DATA_DIR / "reports"
TICKETS_FILE = DATA_DIR / "tickets.jsonl"
BLOCKLIST_FILE = DATA_DIR / "blocklist.txt"
ISOLATED_FILE = DATA_DIR / "isolated_hosts.txt"


def initialize_ir_data() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    INCIDENTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if not BLOCKLIST_FILE.exists():
        BLOCKLIST_FILE.write_text("", encoding="utf-8")
    if not ISOLATED_FILE.exists():
        ISOLATED_FILE.write_text("", encoding="utf-8")
    if not TICKETS_FILE.exists():
        TICKETS_FILE.write_text("", encoding="utf-8")


def _read_lines(path: Path) -> list[str]:
    initialize_ir_data()
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def _write_unique_line(path: Path, value: str) -> None:
    initialize_ir_data()
    value = str(value or "").strip()
    if not value:
        return
    current = _read_lines(path)
    if value not in current:
        current.append(value)
        path.write_text("\n".join(current) + "\n", encoding="utf-8")


def _remove_line(path: Path, value: str) -> None:
    initialize_ir_data()
    value = str(value or "").strip()
    current = [x for x in _read_lines(path) if x != value]
    path.write_text("\n".join(current) + ("\n" if current else ""), encoding="utf-8")


def read_blocklist() -> list[str]:
    return _read_lines(BLOCKLIST_FILE)


def read_isolated_hosts() -> list[str]:
    return _read_lines(ISOLATED_FILE)


def read_tickets() -> list[dict[str, Any]]:
    initialize_ir_data()
    tickets: list[dict[str, Any]] = []
    if not TICKETS_FILE.exists():
        return tickets
    for line in TICKETS_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            tickets.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return tickets


def read_incidents() -> list[dict[str, Any]]:
    initialize_ir_data()
    incidents: list[dict[str, Any]] = []
    for path in sorted(INCIDENTS_DIR.glob("*.json")):
        try:
            incidents.append(json.loads(path.read_text(encoding="utf-8", errors="replace")))
        except Exception:
            continue
    return incidents


def get_ir_status() -> dict[str, Any]:
    initialize_ir_data()
    return {
        "mode": "dry_run_demo",
        "incidents": read_incidents(),
        "tickets": read_tickets(),
        "blocklist": read_blocklist(),
        "isolated_hosts": read_isolated_hosts(),
        "data_directory": str(DATA_DIR),
    }


def execute_demo_action(action_type: str, target: str, incident_id: str | None = None) -> dict[str, Any]:
    """Apply a demo-only IR action by updating local files, not the real OS/network."""
    initialize_ir_data()
    action_type = str(action_type or "").strip().lower()
    target = str(target or "").strip()
    if not target:
        raise ValueError("No target was provided.")

    commands: list[dict[str, str]] = []
    message = ""

    if action_type == "block_ip":
        _write_unique_line(BLOCKLIST_FILE, target)
        commands = _build_commands_for_ip(target)
        message = f"Demo block applied: {target} was added to data/blocklist.txt."
    elif action_type == "unblock_ip":
        _remove_line(BLOCKLIST_FILE, target)
        message = f"Demo unblock applied: {target} was removed from data/blocklist.txt."
    elif action_type == "isolate_host":
        _write_unique_line(ISOLATED_FILE, target)
        commands = [
            {
                "platform": "Windows host isolation",
                "purpose": "Allow only IR management host and block other traffic",
                "command": f'netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound  # target host: {target}',
            },
            {
                "platform": "Linux host isolation",
                "purpose": "Deny all traffic by default during containment",
                "command": f"sudo ufw default deny incoming && sudo ufw default deny outgoing  # target host: {target}",
            },
        ]
        message = f"Demo isolation applied: {target} was added to data/isolated_hosts.txt."
    elif action_type == "unisolate_host":
        _remove_line(ISOLATED_FILE, target)
        message = f"Demo release applied: {target} was removed from data/isolated_hosts.txt."
    elif action_type == "kill_process":
        commands = [
            {"platform": "Windows", "purpose": "Terminate suspicious PID after approval", "command": f"taskkill /PID {target} /F"},
            {"platform": "Linux", "purpose": "Terminate suspicious PID after approval", "command": f"sudo kill -9 {target}"},
        ]
        message = f"Demo process action prepared for PID/process target {target}."
    else:
        raise ValueError("Unsupported action_type. Use block_ip, unblock_ip, isolate_host, unisolate_host, or kill_process.")

    return {
        "mode": "dry_run_demo",
        "incident_id": incident_id,
        "action_type": action_type,
        "target": target,
        "message": message,
        "commands": commands,
        "blocklist": read_blocklist(),
        "isolated_hosts": read_isolated_hosts(),
        "safety_note": "This endpoint updates demo files only. It does not modify the real firewall or network.",
    }


def create_ir_ticket(incident_id: str | None, title: str, priority: str = "Medium", assignee: str = "SOC-Tier1") -> dict[str, Any]:
    initialize_ir_data()
    tickets = read_tickets()
    ticket = {
        "ticket_id": f"TKT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "incident_id": incident_id or "manual",
        "title": title or "Hybrid IDS Incident",
        "status": "Open",
        "priority": priority or "Medium",
        "assignee": assignee or "SOC-Tier1",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with TICKETS_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(ticket) + "\n")
    return {"ticket": ticket, "tickets": tickets + [ticket]}


def read_ir_report(report_id: str) -> str:
    initialize_ir_data()
    safe_id = Path(str(report_id)).stem
    path = REPORTS_DIR / f"{safe_id}.md"
    if not path.exists():
        raise FileNotFoundError(f"No report found for {safe_id}")
    return path.read_text(encoding="utf-8", errors="replace")
