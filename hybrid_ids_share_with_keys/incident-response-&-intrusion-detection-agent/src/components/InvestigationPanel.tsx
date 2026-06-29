import React, { useState } from "react";
import {
  FileText,
  Map,
  AlertOctagon,
  Activity,
  ClipboardList,
  CheckCircle,
  Shield,
  Crosshair,
  Zap,
  Radio,
  Network,
  Clock,
  Hash,
  Server,
  ChevronRight,
  Sparkles,
  BarChart3,
  Lock
} from "lucide-react";
import { Incident } from "../types";

interface InvestigationPanelProps {
  activeIncident: Incident | null;
  onOpenTicket: (title: string, priority: string) => void;
  isOpeningTicket: boolean;
}

/* ─── helpers ─────────────────────────────────────────────── */
const severityConfig: Record<string, { ring: string; badge: string; dot: string; label: string }> = {
  critical: {
    ring: "border-red-500/40 shadow-red-500/10",
    badge: "bg-red-500/15 text-red-400 border border-red-500/30",
    dot: "bg-red-400",
    label: "CRITICAL",
  },
  high: {
    ring: "border-orange-500/40 shadow-orange-500/10",
    badge: "bg-orange-500/15 text-orange-400 border border-orange-500/30",
    dot: "bg-orange-400",
    label: "HIGH",
  },
  medium: {
    ring: "border-yellow-500/40 shadow-yellow-500/10",
    badge: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30",
    dot: "bg-yellow-400",
    label: "MEDIUM",
  },
  low: {
    ring: "border-emerald-500/40 shadow-emerald-500/10",
    badge: "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30",
    dot: "bg-emerald-400",
    label: "LOW",
  },
};
const getSev = (s: string) => severityConfig[s?.toLowerCase()] ?? severityConfig.low;

const cvssColor = (n: number) =>
  n >= 9 ? "text-red-400" : n >= 7 ? "text-orange-400" : n >= 4 ? "text-yellow-400" : "text-emerald-400";

/** Very simple markdown → JSX renderer for the report tab */
function MarkdownRenderer({ raw }: { raw: string }) {
  const lines = raw.split("\n");
  const nodes: React.ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // H1
    if (line.startsWith("# ")) {
      nodes.push(
        <h1 key={i} className="text-base font-black text-white mt-4 mb-1 pb-1.5 border-b border-slate-700 tracking-tight">
          {line.slice(2)}
        </h1>
      );
    }
    // H2
    else if (line.startsWith("## ")) {
      nodes.push(
        <h2 key={i} className="text-[13px] font-bold text-indigo-300 mt-3.5 mb-1 flex items-center gap-1.5">
          <span className="w-1 h-4 bg-indigo-500 rounded-full inline-block" />
          {line.slice(3)}
        </h2>
      );
    }
    // H3
    else if (line.startsWith("### ")) {
      nodes.push(
        <h3 key={i} className="text-[11px] font-bold text-slate-300 uppercase tracking-widest mt-2.5 mb-0.5">
          {line.slice(4)}
        </h3>
      );
    }
    // horizontal rule
    else if (/^---+$/.test(line.trim())) {
      nodes.push(<hr key={i} className="border-slate-800 my-2" />);
    }
    // bullet
    else if (/^[-*] /.test(line)) {
      nodes.push(
        <div key={i} className="flex items-start gap-2 py-0.5">
          <span className="mt-[5px] w-1.5 h-1.5 rounded-full bg-indigo-500 shrink-0" />
          <span className="text-[11px] text-slate-300 leading-relaxed">
            {renderInline(line.slice(2))}
          </span>
        </div>
      );
    }
    // bold key:value shorthand  **Key:** value
    else if (line.trim().startsWith("**") && line.includes(":**")) {
      const colonIdx = line.indexOf(":**");
      const key = line.slice(line.indexOf("**") + 2, colonIdx);
      const value = line.slice(colonIdx + 3).replace(/\*\*/g, "").trim();
      nodes.push(
        <div key={i} className="flex items-start gap-1.5 py-0.5 font-mono text-[10px]">
          <span className="text-slate-500 shrink-0">{key}:</span>
          <span className="text-slate-200">{value}</span>
        </div>
      );
    }
    // code block
    else if (line.startsWith("```")) {
      const lang = line.slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      nodes.push(
        <pre key={i} className="bg-slate-900 border border-slate-800 rounded-lg p-3 my-2 overflow-x-auto text-[10px] text-emerald-300 font-mono leading-relaxed">
          {codeLines.join("\n")}
        </pre>
      );
    }
    // paragraph / text
    else if (line.trim() !== "") {
      nodes.push(
        <p key={i} className="text-[11px] text-slate-400 leading-relaxed">
          {renderInline(line)}
        </p>
      );
    }
    // blank line — small spacer
    else {
      nodes.push(<div key={i} className="h-1" />);
    }
    i++;
  }
  return <div className="flex flex-col gap-0.5">{nodes}</div>;
}

function renderInline(text: string): React.ReactNode {
  // bold **...**  and `code`
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, idx) => {
    if (part.startsWith("**") && part.endsWith("**"))
      return <strong key={idx} className="text-white font-semibold">{part.slice(2, -2)}</strong>;
    if (part.startsWith("`") && part.endsWith("`"))
      return <code key={idx} className="bg-slate-800 text-indigo-300 px-1 py-0.5 rounded text-[10px] font-mono">{part.slice(1, -1)}</code>;
    return part;
  });
}

/* ─── main component ──────────────────────────────────────── */
export default function InvestigationPanel({ activeIncident, onOpenTicket, isOpeningTicket }: InvestigationPanelProps) {
  const [activeTab, setActiveTab] = useState<"findings" | "report">("findings");
  const [ticketPriority, setTicketPriority] = useState<string>("High");
  const [ticketCreated, setTicketCreated] = useState<boolean>(false);

  const handleCreateTicket = () => {
    if (!activeIncident) return;
    const title = `Incident ${activeIncident.id} escalation — ${activeIncident.attack_type} on ${activeIncident.target_host}`;
    onOpenTicket(title, ticketPriority);
    setTicketCreated(true);
    setTimeout(() => setTicketCreated(false), 4000);
  };

  /* empty state */
  if (!activeIncident) {
    return (
      <div className="flex flex-col items-center justify-center h-full bg-slate-900 border border-slate-800 rounded-xl p-8 text-center gap-4" id="investigation-placeholder">
        <div className="relative">
          <div className="w-20 h-20 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center">
            <Activity className="w-9 h-9 text-indigo-400 animate-pulse" />
          </div>
          <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-amber-400 animate-ping" />
        </div>
        <div>
          <h3 className="text-sm font-bold text-white tracking-tight">SecOps Forensics Engine Idle</h3>
          <p className="text-xs text-slate-500 max-w-xs mx-auto mt-1.5 leading-relaxed">
            Upload a network flow capture and trigger the autonomous AI Incident Responder to begin forensic analysis.
          </p>
        </div>
        <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2">
          <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
          <span className="text-[10px] text-slate-500 font-mono">SOAR ENGINE LISTENING...</span>
        </div>
      </div>
    );
  }

  const sev = getSev(activeIncident.severity);

  return (
    <div className="flex flex-col h-full bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden" id="investigation-details-panel">

      {/* ── Incident identity bar ─────────────────────────────── */}
      <div className={`bg-slate-950 border-b border-slate-800 px-4 pt-4 pb-3 flex flex-col gap-2.5`} id="investigation-header">
        {/* top row: id + severity + status */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono font-bold bg-slate-900 text-indigo-300 px-2 py-0.5 rounded-md border border-slate-700">
              {activeIncident.id}
            </span>
            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider flex items-center gap-1 ${sev.badge}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${sev.dot} animate-pulse`} />
              {sev.label}
            </span>
          </div>
          <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full font-mono border ${activeIncident.status === "Mitigated"
            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
            : "bg-amber-500/10 text-amber-400 border-amber-500/30"
            }`}>
            {activeIncident.status}
          </span>
        </div>

        {/* attack type headline */}
        <div className="flex items-start gap-2">
          <Zap className="w-4 h-4 text-indigo-400 mt-0.5 shrink-0" />
          <h2 className="text-sm font-extrabold text-white tracking-tight leading-tight">
            {activeIncident.attack_type}
          </h2>
        </div>

        {/* meta pills row */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="flex items-center gap-1 text-[10px] text-slate-400 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded-md">
            <Server className="w-3 h-3 text-indigo-400" />
            {activeIncident.target_host}
          </span>
          <span className="flex items-center gap-1 text-[10px] font-mono text-red-400 bg-red-500/5 border border-red-500/20 px-2 py-0.5 rounded-md">
            <Crosshair className="w-3 h-3" />
            {activeIncident.source_ip}
          </span>
          <span className="flex items-center gap-1 text-[10px] font-mono text-slate-500 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded-md">
            <Clock className="w-3 h-3" />
            {new Date(activeIncident.timestamp).toLocaleTimeString()}
          </span>
        </div>

        {/* tab toggle */}
        <div className="flex gap-1 bg-slate-900 p-0.5 rounded-lg border border-slate-800 self-start mt-0.5">
          {(["findings", "report"] as const).map((tab) => (
            <button
              key={tab}
              id={`tab-${tab}-btn`}
              onClick={() => setActiveTab(tab)}
              className={`text-[10px] px-3 py-1.5 rounded-md font-semibold transition-all flex items-center gap-1.5 ${activeTab === tab
                ? "bg-indigo-600 text-white shadow-sm shadow-indigo-500/30"
                : "text-slate-400 hover:text-white"
                }`}
            >
              {tab === "findings" ? <Sparkles className="w-3 h-3" /> : <FileText className="w-3 h-3" />}
              {tab === "findings" ? "AI Findings" : "Forensic Report"}
            </button>
          ))}
        </div>
      </div>

      {/* ── Tab body ─────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto p-4" id="investigation-tabs-body">

        {/* ════ FINDINGS TAB ════════════════════════════════════ */}
        {activeTab === "findings" && (
          <div className="flex flex-col gap-3" id="tab-findings-content">

            {/* CVSS + traffic stats row */}
            <div className="grid grid-cols-2 gap-3">

              {/* CVSS card */}
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex flex-col gap-1.5">
                <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
                  <BarChart3 className="w-3 h-3" /> CVSS v3.1
                </span>
                <div className="flex items-end gap-1.5">
                  <span className={`text-3xl font-black tabular-nums ${cvssColor(activeIncident.cvss)}`}>
                    {activeIncident.cvss.toFixed(1)}
                  </span>
                  <span className="text-slate-600 text-[10px] mb-1">/ 10</span>
                </div>
                {/* mini bar */}
                <div className="h-1 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${activeIncident.cvss >= 9 ? "bg-red-500" :
                      activeIncident.cvss >= 7 ? "bg-orange-500" :
                        activeIncident.cvss >= 4 ? "bg-yellow-500" : "bg-emerald-500"
                      }`}
                    style={{ width: `${(activeIncident.cvss / 10) * 100}%` }}
                  />
                </div>
                <code className="text-[8px] text-slate-600 font-mono truncate mt-0.5">
                  {activeIncident.cvss_vector || "CVSS:3.1/AV:N/AC:L/PR:N"}
                </code>
              </div>

              {/* Network stats card */}
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex flex-col gap-2">
                <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
                  <Network className="w-3 h-3" /> Traffic Stats
                </span>
                {activeIncident.traffic_stats ? (
                  <div className="flex flex-col gap-1.5">
                    {[
                      ["Protocol", activeIncident.traffic_stats.protocol],
                      ["Packets", activeIncident.traffic_stats.packets],
                      ["Bytes", activeIncident.traffic_stats.bytes.toLocaleString()],
                    ].map(([k, v]) => (
                      <div key={String(k)} className="flex justify-between items-center">
                        <span className="text-[9px] text-slate-600 font-mono">{k}</span>
                        <span className="text-[10px] font-bold text-slate-300 font-mono">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col gap-1.5 text-[9px] font-mono text-slate-600">
                    <div className="flex justify-between"><span>Target IP</span><span className="text-indigo-400">{activeIncident.target_ip}</span></div>
                    <div className="flex justify-between"><span>Source IP</span><span className="text-red-400">{activeIncident.source_ip}</span></div>
                    <div className="flex justify-between"><span>Host</span><span className="text-slate-400">{activeIncident.target_host}</span></div>
                  </div>
                )}
              </div>
            </div>

            {/* MITRE ATT&CK card */}
            <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden" id="mitre-attack-panel">
              <div className="flex items-center justify-between px-3.5 py-2.5 border-b border-slate-800 bg-slate-900/60">
                <div className="flex items-center gap-1.5">
                  <Map className="w-3.5 h-3.5 text-indigo-400" />
                  <span className="text-[11px] font-bold text-slate-200">MITRE ATT&CK® Mapping</span>
                </div>
                <a
                  href={`https://attack.mitre.org/techniques/${activeIncident.mitre.id.replace(".", "/")}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[9px] text-indigo-400 hover:text-indigo-300 font-mono underline underline-offset-2"
                >
                  {activeIncident.mitre.id} ↗
                </a>
              </div>
              <div className="p-3.5 flex flex-col gap-2.5">
                {/* tactic → technique flow */}
                <div className="flex items-center gap-2">
                  <div className="flex-1 bg-slate-900 border border-slate-800 rounded-lg p-2">
                    <p className="text-[8px] font-bold text-slate-500 uppercase tracking-widest">Tactic</p>
                    <p className="text-xs font-bold text-sky-400 mt-0.5">{activeIncident.mitre.tactic}</p>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-600 shrink-0" />
                  <div className="flex-1 bg-slate-900 border border-indigo-500/20 rounded-lg p-2">
                    <p className="text-[8px] font-bold text-slate-500 uppercase tracking-widest">Technique</p>
                    <p className="text-xs font-bold text-indigo-300 mt-0.5">{activeIncident.mitre.name}</p>
                  </div>
                </div>
                <p className="text-[10px] text-slate-500 leading-relaxed bg-slate-900/40 px-2.5 py-2 rounded-lg border-l-2 border-indigo-500/40">
                  Adversary leveraged <span className="text-slate-300 font-semibold">{activeIncident.mitre.name}</span> ({activeIncident.mitre.tactic}) to compromise endpoint infrastructure and escalate access vectors.
                </p>
              </div>
            </div>

            {/* AI Investigator Summary */}
            <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden" id="forensic-notes-panel">
              <div className="flex items-center gap-1.5 px-3.5 py-2.5 border-b border-slate-800 bg-slate-900/60">
                <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                <span className="text-[11px] font-bold text-slate-200">Gemini IR Investigator Analysis</span>
                <span className="ml-auto text-[9px] bg-indigo-500/10 text-indigo-400 px-1.5 py-0.5 rounded font-mono border border-indigo-500/20">AI Generated</span>
              </div>
              <div className="p-3.5">
                <p className="text-[11px] text-slate-300 leading-[1.75] font-sans">
                  {activeIncident.investigation_summary}
                </p>
              </div>
            </div>

            {/* Victim Intel */}
            <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden" id="victim-intel-panel">
              <div className="flex items-center gap-1.5 px-3.5 py-2.5 border-b border-slate-800 bg-slate-900/60">
                <Shield className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-[11px] font-bold text-slate-200">Target Intel</span>
              </div>
              <div className="p-3.5 grid grid-cols-3 gap-2">
                {[
                  { label: "Asset", value: activeIncident.target_host, color: "text-slate-300" },
                  { label: "Victim IP", value: activeIncident.target_ip, color: "text-indigo-400" },
                  { label: "Attacker", value: activeIncident.source_ip, color: "text-red-400" },
                ].map(({ label, value, color }) => (
                  <div key={label} className="bg-slate-900 border border-slate-800 rounded-lg p-2 flex flex-col gap-1">
                    <span className="text-[8px] font-bold text-slate-600 uppercase tracking-widest">{label}</span>
                    <span className={`text-[10px] font-bold font-mono ${color} truncate`} title={value}>{value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Escalation ticket */}
            <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden" id="incident-ticketing-workflow">
              <div className="flex items-center justify-between px-3.5 py-2.5 border-b border-slate-800 bg-slate-900/60">
                <div className="flex items-center gap-1.5">
                  <ClipboardList className="w-3.5 h-3.5 text-slate-400" />
                  <span className="text-[11px] font-bold text-slate-200">Escalate IT Service Ticket</span>
                </div>
                <span className="text-[9px] bg-indigo-500/10 text-indigo-400 px-1.5 py-0.5 rounded font-mono border border-indigo-500/20">Jira / ServiceNow</span>
              </div>
              <div className="p-3.5 flex items-center gap-3">
                <div className="flex-1 flex flex-col gap-1">
                  <label className="text-[8px] font-bold text-slate-500 uppercase tracking-widest">Priority Level</label>
                  <select
                    id="ticket-priority-select"
                    value={ticketPriority}
                    onChange={(e) => setTicketPriority(e.target.value)}
                    className="bg-slate-900 border border-slate-700 text-xs text-slate-300 px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-indigo-500 transition-colors"
                  >
                    <option value="Low">Low Priority</option>
                    <option value="Medium">Medium Priority</option>
                    <option value="High">High Priority</option>
                    <option value="Critical">Critical — P0</option>
                  </select>
                </div>
                <button
                  id="create-escalation-ticket-btn"
                  onClick={handleCreateTicket}
                  disabled={isOpeningTicket || ticketCreated}
                  className={`self-end flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition-all shadow-sm ${ticketCreated
                    ? "bg-emerald-600/20 border border-emerald-500/30 text-emerald-400"
                    : "bg-indigo-600 hover:bg-indigo-500 text-white shadow-indigo-500/20 disabled:opacity-50"
                    }`}
                >
                  {ticketCreated ? (
                    <><CheckCircle className="w-3.5 h-3.5" /> Ticket Logged!</>
                  ) : (
                    <><ClipboardList className="w-3.5 h-3.5" /> Generate Ticket</>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ════ REPORT TAB ══════════════════════════════════════ */}
        {activeTab === "report" && (
          <div className="flex flex-col gap-3" id="tab-report-content">

            {/* report header bar */}
            <div className="flex items-center justify-between bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-lg bg-indigo-500/15 border border-indigo-500/20 flex items-center justify-center">
                  <FileText className="w-3.5 h-3.5 text-indigo-400" />
                </div>
                <div>
                  <p className="text-[11px] font-bold text-slate-200">Forensic Investigation Report</p>
                  <p className="text-[9px] text-slate-600 font-mono">{activeIncident.id} · Generated by Gemini AI</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5">
                <Lock className="w-3 h-3 text-slate-600" />
                <span className="text-[9px] text-slate-600 font-mono">TLP:RED</span>
              </div>
            </div>

            {/* report body */}
            <div
              id="markdown-viewer"
              className="bg-slate-950 border border-slate-800 rounded-xl p-4 overflow-y-auto max-h-[400px]"
              style={{ minHeight: "340px" }}
            >
              {activeIncident.markdown_report ? (
                <MarkdownRenderer raw={activeIncident.markdown_report} />
              ) : (
                <div className="flex flex-col items-center justify-center h-48 gap-3 text-center">
                  <div className="w-12 h-12 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center">
                    <FileText className="w-5 h-5 text-slate-600" />
                  </div>
                  <p className="text-xs text-slate-600 italic">Forensic report is generating or unavailable.</p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
