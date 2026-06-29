import React, { useState, useEffect, useRef } from "react";
import { 
  Terminal, 
  Cpu, 
  Network, 
  ShieldCheck, 
  ShieldAlert, 
  XCircle, 
  Play, 
  RefreshCw, 
  Layers, 
  AlertTriangle 
} from "lucide-react";
import { EndpointAgent, FirewallRule, Process } from "../types";

interface EndpointConsoleProps {
  endpoints: Record<string, EndpointAgent>;
  selectedHostname: string;
  onSelectHost: (hostname: string) => void;
  onKillProcess: (hostname: string, pid: number) => void;
  actionRunningPid: number | null;
}

export default function EndpointConsole({ 
  endpoints, 
  selectedHostname, 
  onSelectHost, 
  onKillProcess, 
  actionRunningPid 
}: EndpointConsoleProps) {
  const [activeConsoleTab, setActiveConsoleTab] = useState<"terminal" | "firewall" | "processes">("terminal");
  const terminalEndRef = useRef<HTMLDivElement>(null);

  const currentAgent = endpoints[selectedHostname] || Object.values(endpoints)[0];

  // Auto-scroll terminal to bottom
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [currentAgent?.terminalLogs, activeConsoleTab]);

  if (!currentAgent) {
    return (
      <div className="flex flex-col items-center justify-center h-full bg-slate-900 border border-slate-800 rounded-xl p-6 text-slate-500 text-xs">
        No active endpoint connections found.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4 h-full bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-2xl overflow-y-auto" id="endpoint-agent-console-panel">
      
      {/* Header and Host Selector */}
      <div className="flex justify-between items-center border-b border-slate-800 pb-3" id="console-header">
        <div className="flex items-center gap-2.5">
          <div className="p-2 bg-indigo-500/10 text-indigo-400 rounded-lg">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white tracking-tight">Endpoint Agent Console</h2>
            <p className="text-[10px] text-slate-400">Victim Host local process & firewall control</p>
          </div>
        </div>

        {/* Host dropdown selector */}
        <select
          id="host-console-select"
          value={selectedHostname}
          onChange={(e) => onSelectHost(e.target.value)}
          className="bg-slate-950 border border-slate-800 text-xs text-slate-300 font-mono px-2 py-1.5 rounded-lg focus:outline-none focus:border-indigo-500"
        >
          {Object.keys(endpoints).map((hostname) => (
            <option key={hostname} value={hostname}>{hostname} ({endpoints[hostname].ip})</option>
          ))}
        </select>
      </div>

      {/* Target Host Details Banner */}
      <div className="grid grid-cols-4 gap-2.5 bg-slate-950 border border-slate-800/80 rounded-xl p-3" id="host-specs-card">
        <div className="flex flex-col">
          <span className="text-[8px] font-bold text-slate-500 uppercase">OS Environment</span>
          <span className="text-[11px] font-semibold text-slate-300 mt-0.5">{currentAgent.os}</span>
        </div>
        <div className="flex flex-col">
          <span className="text-[8px] font-bold text-slate-500 uppercase">Connection IP</span>
          <span className="text-[11px] font-semibold text-indigo-400 font-mono mt-0.5">{currentAgent.ip}</span>
        </div>
        <div className="flex flex-col">
          <span className="text-[8px] font-bold text-slate-500 uppercase">Socket Sockets</span>
          <span className="text-[11px] font-semibold text-slate-300 mt-0.5">{currentAgent.connectionsCount} links</span>
        </div>
        <div className="flex flex-col items-end">
          <span className="text-[8px] font-bold text-slate-500 uppercase">Agent Status</span>
          <span className={`inline-flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 rounded-full mt-1 ${
            currentAgent.status === "ONLINE" 
              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" 
              : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${currentAgent.status === "ONLINE" ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
            {currentAgent.status}
          </span>
        </div>
      </div>

      {/* Console Tab Selectors */}
      <div className="flex border-b border-slate-800/60 pb-px" id="console-tab-headers">
        <button
          id="console-tab-term"
          onClick={() => setActiveConsoleTab("terminal")}
          className={`text-xs px-4 py-2 font-medium border-b-2 transition-all flex items-center gap-1.5 ${
            activeConsoleTab === "terminal" 
              ? "border-indigo-500 text-indigo-400 bg-indigo-500/5 font-semibold" 
              : "border-transparent text-slate-400 hover:text-white"
          }`}
        >
          <Terminal className="w-3.5 h-3.5" /> Agent Shell Logs
        </button>
        <button
          id="console-tab-fw"
          onClick={() => setActiveConsoleTab("firewall")}
          className={`text-xs px-4 py-2 font-medium border-b-2 transition-all flex items-center gap-1.5 ${
            activeConsoleTab === "firewall" 
              ? "border-indigo-500 text-indigo-400 bg-indigo-500/5 font-semibold" 
              : "border-transparent text-slate-400 hover:text-white"
          }`}
        >
          <Layers className="w-3.5 h-3.5" /> IPTables Firewall
        </button>
        <button
          id="console-tab-proc"
          onClick={() => setActiveConsoleTab("processes")}
          className={`text-xs px-4 py-2 font-medium border-b-2 transition-all flex items-center gap-1.5 ${
            activeConsoleTab === "processes" 
              ? "border-indigo-500 text-indigo-400 bg-indigo-500/5 font-semibold" 
              : "border-transparent text-slate-400 hover:text-white"
          }`}
        >
          <Cpu className="w-3.5 h-3.5" /> Processes
        </button>
      </div>

      {/* Tab Panels */}
      <div className="flex-1 min-h-[280px]" id="console-tabs-content-area">
        
        {/* Tab 1: Live Terminal Shell logs */}
        {activeConsoleTab === "terminal" && (
          <div className="flex flex-col h-full bg-slate-950 border border-slate-850 rounded-xl p-4 font-mono text-[11px] text-slate-300" id="terminal-pane">
            <div className="flex justify-between items-center text-[10px] text-slate-500 border-b border-slate-900 pb-2 mb-2">
              <span>MTLS CONTROL ENDPOINT ESTABLISHED</span>
              <span>PORT 3000 SECURE</span>
            </div>
            
            <div className="flex-1 overflow-y-auto max-h-[220px] flex flex-col gap-1.5 pr-2 select-text font-mono">
              {currentAgent.terminalLogs.map((log, idx) => (
                <div key={idx} className="leading-relaxed">
                  <span className="text-indigo-500/80 mr-1.5">&gt;</span>
                  <span className={
                    log.includes("[IR-ACTION]") ? "text-amber-400" :
                    log.includes("Alert:") ? "text-red-400" : "text-slate-300"
                  }>
                    {log}
                  </span>
                </div>
              ))}
              {actionRunningPid && (
                <div className="flex items-center gap-2 text-indigo-400 font-bold animate-pulse mt-1">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Executing agent process shutdown...</span>
                </div>
              )}
              <div ref={terminalEndRef} />
            </div>
          </div>
        )}

        {/* Tab 2: Firewall IPTables list */}
        {activeConsoleTab === "firewall" && (
          <div className="flex flex-col gap-2" id="firewall-rule-list">
            <div className="flex justify-between items-center text-[10px] text-slate-500 px-1">
              <span>LOCAL IPTABLES SYSTEM FILTER CHAINS</span>
              <span>{currentAgent.firewallRules.length} ACTIVE RULES</span>
            </div>

            <div className="bg-slate-950 border border-slate-850 rounded-xl overflow-hidden overflow-y-auto max-h-[240px]">
              <table className="w-full text-[10px] text-left font-mono">
                <thead className="bg-slate-900 border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="px-3 py-2">Dir</th>
                    <th className="px-2 py-2">Proto</th>
                    <th className="px-2 py-2">Port</th>
                    <th className="px-2 py-2">Source</th>
                    <th className="px-2 py-2">Dest</th>
                    <th className="px-3 py-2 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-900 text-slate-300">
                  {currentAgent.firewallRules.map((rule, idx) => (
                    <tr key={idx} className={`hover:bg-slate-900/60 transition-colors ${rule.id.includes('isolation') ? 'bg-indigo-950/20' : ''}`}>
                      <td className="px-3 py-2 font-bold">
                        <span className={rule.direction === "INBOUND" ? "text-sky-400" : "text-purple-400"}>
                          {rule.direction}
                        </span>
                      </td>
                      <td className="px-2 py-2 uppercase">{rule.proto}</td>
                      <td className="px-2 py-2">{rule.port}</td>
                      <td className="px-2 py-2 truncate max-w-[80px]" title={rule.source}>{rule.source}</td>
                      <td className="px-2 py-2 truncate max-w-[80px]" title={rule.destination}>{rule.destination}</td>
                      <td className="px-3 py-2 text-right">
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                          rule.action === "ALLOW" 
                            ? "bg-emerald-500/15 text-emerald-400" 
                            : "bg-red-500/15 text-red-400"
                        }`}>
                          {rule.action}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {currentAgent.status === "ISOLATED" && (
              <div className="bg-indigo-950/20 border border-indigo-900/40 rounded-lg p-2.5 flex items-start gap-2 text-[10px] text-indigo-300 mt-1">
                <ShieldAlert className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold uppercase tracking-wide">Isolation Active:</span> All ingress and egress chains flushed. Standard routing disabled. Allowing only IR controller control traffic.
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Running Processes */}
        {activeConsoleTab === "processes" && (
          <div className="flex flex-col gap-2" id="process-list">
            <div className="flex justify-between items-center text-[10px] text-slate-500 px-1">
              <span>ACTIVE RAM PROCESS RESOURCE DESCRIPTORS</span>
              <span>PID SCAN ONLINE</span>
            </div>

            <div className="bg-slate-950 border border-slate-850 rounded-xl overflow-hidden overflow-y-auto max-h-[240px]">
              <table className="w-full text-[10px] text-left font-mono">
                <thead className="bg-slate-900 border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="px-3 py-2">PID</th>
                    <th className="px-2 py-2">Process Name</th>
                    <th className="px-2 py-2 text-right">CPU%</th>
                    <th className="px-2 py-2 text-right">MEM%</th>
                    <th className="px-2 py-2 text-center">Status</th>
                    <th className="px-3 py-2 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-900 text-slate-300">
                  {currentAgent.processes.map((proc) => (
                    <tr key={proc.pid} className={`hover:bg-slate-900/60 transition-colors ${
                      proc.status === "Suspicious" ? "bg-red-500/5 text-red-300" : ""
                    }`}>
                      <td className="px-3 py-2 font-bold text-slate-500">{proc.pid}</td>
                      <td className="px-2 py-2 truncate max-w-[100px]" title={proc.name}>
                        {proc.name}
                      </td>
                      <td className="px-2 py-2 text-right">{proc.cpu.toFixed(1)}%</td>
                      <td className="px-2 py-2 text-right">{proc.memory.toFixed(1)}%</td>
                      <td className="px-2 py-2 text-center">
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                          proc.status === "Running" ? "bg-slate-900 text-slate-400" :
                          proc.status === "Suspicious" ? "bg-red-500/10 text-red-400 border border-red-500/20" :
                          "bg-slate-950 text-slate-600 line-through"
                        }`}>
                          {proc.status}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-right">
                        {proc.status !== "Defunct" ? (
                          <button
                            id={`kill-btn-${proc.pid}`}
                            onClick={() => onKillProcess(currentAgent.hostname, proc.pid)}
                            disabled={actionRunningPid === proc.pid}
                            className={`px-2 py-1 rounded text-[9px] font-bold transition-all ${
                              proc.status === "Suspicious"
                                ? "bg-red-600 hover:bg-red-500 text-white shadow-sm"
                                : "bg-slate-800 hover:bg-slate-700 text-slate-300"
                            }`}
                          >
                            Kill
                          </button>
                        ) : (
                          <span className="text-slate-600 font-bold text-[9px] pr-2">Terminated</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
