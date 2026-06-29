import React, { useEffect, useState } from "react";
import {
  ShieldCheck,
  Satellite,
  RefreshCw,
  ArrowRightCircle,
  Database,
  AlertTriangle,
  Play,
  Settings,
  Server,
  FileText,
} from "lucide-react";
import { Incident } from "../types";

interface NetworkParserProps {
  activeIncident: Incident | null;
  onRunResponder: (
    manualContext: string,
    targetHost: string,
    businessImpact: string,
    systemRole: string
  ) => void;
  isLoading: boolean;
  endpointsList: string[];
}

export default function NetworkParser({
  activeIncident,
  onRunResponder,
  isLoading,
  endpointsList,
}: NetworkParserProps) {
  const [targetHost, setTargetHost] = useState<string>(activeIncident?.target_host || endpointsList[0] || "prod-web-01");
  const [criticality, setCriticality] = useState<string>("High");
  const [systemRole, setSystemRole] = useState<string>("Public Web Gateway");
  const [manualLogs, setManualLogs] = useState<string>(
    "Add firewall, endpoint, web server, authentication, or SOC analyst notes here before running the AI responder."
  );

  useEffect(() => {
    if (activeIncident?.target_host) {
      setTargetHost(activeIncident.target_host);
    }
  }, [activeIncident?.id, activeIncident?.target_host]);

  const runResponder = () => {
    const enrichedContext = [
      `Business Impact: ${criticality}`,
      `Server/Application Role: ${systemRole}`,
      `SOC Observables / Manual Logs: ${manualLogs}`,
    ].join("\n");
    onRunResponder(enrichedContext, targetHost, criticality, systemRole);
  };

  return (
    <div className="flex flex-col gap-5 h-full bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-2xl overflow-y-auto" id="hybrid-ids-handoff-container">
      <div className="flex items-center gap-3 border-b border-slate-800 pb-3" id="handoff-header">
        <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-lg">
          <Satellite className="w-5 h-5" />
        </div>
        <div>
          <h2 className="text-md font-semibold text-white tracking-tight">Hybrid IDS Handoff Receiver</h2>
          <p className="text-xs text-slate-400">Real incidents are received only from the Hybrid IDS dashboard.</p>
        </div>
      </div>

      <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-4 flex flex-col gap-3" id="real-mode-notice">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span className="text-sm font-bold text-slate-100">Real IDS Handoff Mode</span>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          Quick-inject templates and local mock uploads are removed. Upload PCAP/CSV files in the Hybrid IDS system,
          run detection, then click <span className="text-indigo-300 font-semibold">Send to SOAR Incident Response</span>.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-3" id="handoff-flow-steps">
        <div className="flex items-center justify-between bg-slate-950/40 border border-slate-800 rounded-xl p-3">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-indigo-400" />
            <span className="text-xs font-semibold text-slate-300">1. Analyze PCAP/CSV in Hybrid IDS</span>
          </div>
          <ArrowRightCircle className="w-4 h-4 text-slate-600" />
        </div>
        <div className="flex items-center justify-between bg-slate-950/40 border border-slate-800 rounded-xl p-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <span className="text-xs font-semibold text-slate-300">2. IDS sends binary, multiclass, rules, and zero-day output</span>
          </div>
          <ArrowRightCircle className="w-4 h-4 text-slate-600" />
        </div>
        <div className="flex items-center justify-between bg-slate-950/40 border border-slate-800 rounded-xl p-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span className="text-xs font-semibold text-slate-300">3. SOAR creates ticket, report, and containment plan</span>
          </div>
        </div>
      </div>

      <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-4" id="handoff-status-card">
        <div className="flex items-center justify-between gap-3">
          <div>
            <span className="text-[10px] font-bold text-slate-500 uppercase">Current State</span>
            <p className="text-sm text-slate-300 mt-1">
              {activeIncident ? (
                <>
                  Selected incident <span className="text-indigo-300 font-semibold">{activeIncident.id}</span> is ready for AI response.
                </>
              ) : (
                <>
                  Waiting for new incidents from <span className="text-indigo-300 font-semibold">/api/ids-ingest</span>.
                </>
              )}
            </p>
            <p className="text-[11px] text-slate-500 mt-1">Endpoint agents loaded: {endpointsList.length}</p>
          </div>
          <button
            onClick={() => window.location.reload()}
            className="text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-700"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} /> Refresh
          </button>
        </div>
      </div>

      {activeIncident && (
        <div className="flex flex-col gap-3.5 bg-slate-950 border border-slate-800 rounded-xl p-4" id="selected-ids-incident-panel">
          <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5 text-indigo-400" /> Selected Hybrid IDS Incident
          </span>
          <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
            <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-2">
              <span className="text-slate-500 block text-[9px] uppercase font-bold">Incident ID</span>
              <span className="text-indigo-300 break-all">{activeIncident.id}</span>
            </div>
            <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-2">
              <span className="text-slate-500 block text-[9px] uppercase font-bold">Severity</span>
              <span className="text-red-300">{activeIncident.severity}</span>
            </div>
            <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-2 col-span-2">
              <span className="text-slate-500 block text-[9px] uppercase font-bold">Attack / Finding</span>
              <span className="text-slate-200">{activeIncident.attack_type}</span>
            </div>
            <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-2">
              <span className="text-slate-500 block text-[9px] uppercase font-bold">Source IP</span>
              <span className="text-red-300">{activeIncident.source_ip}</span>
            </div>
            <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-2">
              <span className="text-slate-500 block text-[9px] uppercase font-bold">Target IP</span>
              <span className="text-slate-300">{activeIncident.target_ip}</span>
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-col gap-3.5 bg-slate-950 border border-slate-800 rounded-xl p-4" id="manual-context-panel">
        <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
          <Settings className="w-3.5 h-3.5 text-indigo-400" /> Analyst Context for AI Responder
        </span>

        <div className="grid grid-cols-2 gap-2.5">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-bold text-slate-500 uppercase">Victim Host Endpoint</label>
            <select
              id="target-host-select"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-xs text-slate-300 px-2 py-1.5 rounded-lg focus:outline-none focus:border-indigo-500"
            >
              {endpointsList.map((ep, idx) => (
                <option key={idx} value={ep}>{ep}</option>
              ))}
              {!endpointsList.includes(targetHost) && <option value={targetHost}>{targetHost}</option>}
            </select>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-bold text-slate-500 uppercase">Business Impact</label>
            <select
              id="criticality-select"
              value={criticality}
              onChange={(e) => setCriticality(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-xs text-slate-300 px-2 py-1.5 rounded-lg focus:outline-none focus:border-indigo-500"
            >
              <option value="Low">Low (Dev Environment)</option>
              <option value="Medium">Medium (User LAN)</option>
              <option value="High">High (DMZ Portal)</option>
              <option value="Critical">Critical (Core Data Vault)</option>
            </select>
          </div>
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-[10px] font-bold text-slate-500 uppercase">Server Application Role</label>
          <div className="relative">
            <Server className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-2" />
            <input
              id="system-role-input"
              type="text"
              value={systemRole}
              onChange={(e) => setSystemRole(e.target.value)}
              placeholder="e.g. Nginx frontend reverse proxy"
              className="w-full bg-slate-900 border border-slate-800 text-xs text-slate-300 pl-7 pr-2 py-1.5 rounded-lg focus:outline-none focus:border-indigo-500"
            />
          </div>
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-[10px] font-bold text-slate-500 uppercase">SOC Observables / Manual Logs</label>
          <textarea
            id="manual-logs-textarea"
            value={manualLogs}
            onChange={(e) => setManualLogs(e.target.value)}
            rows={3}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-slate-300 focus:outline-none focus:border-indigo-500 resize-none"
            placeholder="Paste firewall, endpoint, auth, web-server, or analyst notes to enrich the AI report..."
          />
        </div>
      </div>

      <button
        id="trigger-forensics-btn"
        onClick={runResponder}
        disabled={isLoading || !activeIncident}
        className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium text-xs py-3 px-4 rounded-xl shadow-lg flex items-center justify-center gap-2 transition-all mt-auto"
      >
        {isLoading ? (
          <>
            <RefreshCw className="w-4 h-4 animate-spin" />
            <span>AI Forensics Agent Investigating...</span>
          </>
        ) : (
          <>
            <Play className="w-4 h-4 fill-white" />
            <span>🚀 Run Autonomous AI Incident Responder</span>
          </>
        )}
      </button>

      {!activeIncident && (
        <p className="text-[10px] text-amber-400 text-center mt-[-10px] flex items-center justify-center gap-1">
          <AlertTriangle className="w-3.5 h-3.5" /> Send a detection from Hybrid IDS first, then run the responder.
        </p>
      )}
    </div>
  );
}
