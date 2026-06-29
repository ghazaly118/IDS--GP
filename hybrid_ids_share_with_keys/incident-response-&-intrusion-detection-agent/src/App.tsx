import React, { useState, useEffect } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Server,
  User,
  Activity,
  Database,
  CheckCircle,
  PlusCircle,
  X,
  Terminal,
  FileText,
  ChevronRight,
  ClipboardList,
  Flame,
  UserX,
  Play,
  RefreshCw
} from "lucide-react";
import { Incident, EndpointAgent, ITTicket } from "./types";
import NetworkParser from "./components/NetworkParser";
import InvestigationPanel from "./components/InvestigationPanel";
import EndpointConsole from "./components/EndpointConsole";
import FirewallStatus from "./components/FirewallStatus";

export default function App() {
  // System State
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [tickets, setTickets] = useState<ITTicket[]>([]);
  const [blocklist, setBlocklist] = useState<string[]>([]);
  const [isolatedHosts, setIsolatedHosts] = useState<string[]>([]);
  const [endpoints, setEndpoints] = useState<Record<string, EndpointAgent>>({});

  // Dashboard navigation states
  const [activeIncidentId, setActiveIncidentId] = useState<string | null>(null);
  const [selectedConsoleHost, setSelectedConsoleHost] = useState<string>("prod-web-01");
  const [showStatusBanner, setShowStatusBanner] = useState<string | null>(null);

  // Loading and action execution states
  const [isLoadingInvestigate, setIsLoadingInvestigate] = useState<boolean>(false);
  const [isOpeningTicket, setIsOpeningTicket] = useState<boolean>(false);
  const [actionRunningPid, setActionRunningPid] = useState<number | null>(null);
  const [actionExecutingType, setActionExecutingType] = useState<string | null>(null);

  // Firewall enforcement status
  const [firewallMode, setFirewallMode] = useState<string>("demo");
  const [paramikoAvailable, setParamikoAvailable] = useState<boolean>(false);
  const [winrmAvailable, setWinrmAvailable] = useState<boolean>(false);

  // Time ticker
  const [currentTime, setCurrentTime] = useState<string>(new Date().toUTCString());

  useEffect(() => {
    fetchSystemStatus();
    fetchFirewallStatus();
    const interval = setInterval(() => {
      setCurrentTime(new Date().toUTCString());
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const fetchSystemStatus = async () => {
    try {
      const res = await fetch("/api/status");
      if (res.ok) {
        const data = await res.json();
        setIncidents(data.incidents);
        setTickets(data.tickets);
        setBlocklist(data.blocklist);
        setIsolatedHosts(data.isolatedHosts);
        setEndpoints(data.endpoints);

        // Select the first investigated incident by default if none selected
        if (!activeIncidentId && data.incidents.length > 0) {
          setActiveIncidentId(data.incidents[0].id);
        }
      }
    } catch (err) {
      console.error("Failed to load dashboard state:", err);
    }
  };

  const fetchFirewallStatus = async () => {
    try {
      const res = await fetch("/api/firewall/status");
      if (res.ok) {
        const data = await res.json();
        setFirewallMode(data.enforcement_mode);
        setParamikoAvailable(data.paramiko_available);
        setWinrmAvailable(data.winrm_available);
        if (data.blocked_ips) setBlocklist(data.blocked_ips);
        if (data.isolated_hosts) setIsolatedHosts(data.isolated_hosts);
      }
    } catch (err) {
      console.error("Failed to load firewall status:", err);
    }
  };

  const handleRunResponder = async (
    manualContext: string,
    targetHost: string,
    businessImpact: string,
    systemRole: string
  ) => {
    if (!activeIncidentId) {
      triggerBanner("No IDS incident selected. Send a detection from Hybrid IDS first.");
      return;
    }

    setIsLoadingInvestigate(true);
    try {
      const res = await fetch("/api/investigate-incident", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          incidentId: activeIncidentId,
          manualContext,
          victimHost: targetHost,
          businessImpact,
          systemRole
        })
      });

      if (res.ok) {
        const incident: Incident = await res.json();

        await fetchSystemStatus();
        setActiveIncidentId(incident.id);
        setSelectedConsoleHost(incident.target_host);

        triggerBanner(`Autonomous AI Incident Responder updated ${incident.id} with a forensic report.`);
      } else {
        const error = await res.text();
        console.error("AI responder failed:", error);
        triggerBanner("AI responder failed. Check the SOAR backend terminal.");
      }
    } catch (err) {
      console.error("Gemini active investigation pipeline failed:", err);
      triggerBanner("Forensic investigation failed to process.");
    } finally {
      setIsLoadingInvestigate(false);
    }
  };

  const handleExecuteAction = async (actionType: string, target: string, details?: string) => {
    setActionExecutingType(actionType);

    // Create UI Delay to show visual feedback for SSH agent execution
    setTimeout(async () => {
      try {
        const res = await fetch("/api/execute-action", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            incidentId: activeIncidentId,
            actionType,
            target,
            details
          })
        });

        if (res.ok) {
          const data = await res.json();
          // Update local endpoints
          setEndpoints(data.endpoints);

          // Re-fetch database stats (blocklist, isolated, incidents status)
          await fetchSystemStatus();
          await fetchFirewallStatus();

          let actionLabel = actionType === "isolate_host" ? `Isolated host ${target}` : `Blocked IP ${target}`;
          triggerBanner(`Autonomous Executor: ${actionLabel} applied.`);
        }
      } catch (err) {
        console.error("Action execution failed:", err);
      } finally {
        setActionExecutingType(null);
      }
    }, 1500);
  };

  const handleKillProcess = async (hostname: string, pid: number) => {
    setActionRunningPid(pid);
    setTimeout(async () => {
      try {
        const res = await fetch("/api/execute-action", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            incidentId: activeIncidentId,
            actionType: "kill_process",
            target: pid.toString(),
            details: `Kill process on ${hostname}`
          })
        });

        if (res.ok) {
          const data = await res.json();
          setEndpoints(data.endpoints);
          await fetchSystemStatus();
          triggerBanner(`Terminated suspicious PID ${pid} on ${hostname}.`);
        }
      } catch (err) {
        console.error("Failed to kill remote pid:", err);
      } finally {
        setActionRunningPid(null);
      }
    }, 1200);
  };

  const handleOpenTicket = async (title: string, priority: string) => {
    setIsOpeningTicket(true);
    try {
      const res = await fetch("/api/tickets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ incidentId: activeIncidentId, title, priority })
      });
      if (res.ok) {
        await fetchSystemStatus();
        triggerBanner("Incident ticket generated and synced in tickets.jsonl");
      }
    } catch (err) {
      console.error("Failed to log ticket:", err);
    } finally {
      setIsOpeningTicket(false);
    }
  };

  const handleUnblock = async (ip: string) => {
    try {
      const res = await fetch("/api/firewall/unblock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
      if (res.ok) {
        await fetchSystemStatus();
        await fetchFirewallStatus();
        triggerBanner(`Unblocked IP ${ip} — rules reversed.`);
      }
    } catch (err) {
      console.error("Unblock failed:", err);
    }
  };

  const handleUnisolate = async (hostname: string) => {
    try {
      const res = await fetch("/api/firewall/unisolate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostname }),
      });
      if (res.ok) {
        await fetchSystemStatus();
        await fetchFirewallStatus();
        triggerBanner(`Released ${hostname} from isolation.`);
      }
    } catch (err) {
      console.error("Unisolate failed:", err);
    }
  };

  const triggerBanner = (message: string) => {
    setShowStatusBanner(message);
    setTimeout(() => {
      setShowStatusBanner(null);
    }, 5000);
  };

  const activeIncident = incidents.find(i => i.id === activeIncidentId) || null;

  // Derive stats counts
  const activeThreatsCount = incidents.filter(i => i.status !== "Mitigated").length;
  const blockedIpsCount = blocklist.length;
  const isolatedHostsCount = incidents.filter(i => i.response_plan.some(act => act.type === "isolate_host" && act.status === "Approved")).length;
  const openTicketsCount = tickets.filter(t => t.status !== "Closed").length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans" id="secops-dashboard-root">

      {/* Top Notification Banner */}
      {showStatusBanner && (
        <div id="status-notification-banner" className="bg-indigo-600 text-white text-xs py-2.5 px-4 font-semibold text-center flex items-center justify-center gap-2 animate-fade-in z-50 border-b border-indigo-500 shadow-md">
          <CheckCircle className="w-4 h-4 shrink-0" />
          <span>{showStatusBanner}</span>
          <button onClick={() => setShowStatusBanner(null)} className="ml-4 hover:opacity-80">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Main Header */}
      <header className="bg-slate-900 border-b border-slate-800/80 px-6 py-4 flex flex-col md:flex-row justify-between items-center gap-4 shadow-md" id="main-secops-header">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center border border-indigo-500 shadow-lg shadow-indigo-500/15">
            <ShieldAlert className="w-5 h-5 text-white animate-pulse" />
          </div>
          <div>
            <h1 className="text-md font-extrabold text-white tracking-tight uppercase">Intrusion Detection & Autonomous Incident Response</h1>
            <p className="text-xs text-slate-400">Coordinated AI Forensics Agent with Real-Time Host Sandboxing</p>
          </div>
        </div>

        {/* Security parameters */}
        <div className="flex items-center gap-4 text-xs font-mono text-slate-400 bg-slate-950/60 border border-slate-800 px-4 py-2 rounded-xl" id="header-system-logs">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <span className="text-slate-300 font-bold">SOAR BACKEND: ONLINE</span>
          </div>
          <span className="text-slate-600">|</span>
          <span>{currentTime}</span>
        </div>
      </header>

      {/* Stats Dashboard Grid */}
      <section className="px-6 py-4 grid grid-cols-2 lg:grid-cols-4 gap-4 bg-slate-900/40 border-b border-slate-800/40" id="stats-dashboard-panel">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex justify-between items-center shadow-lg" id="stat-active-threats">
          <div className="flex flex-col">
            <span className="text-[10px] font-bold text-slate-500 uppercase">Active Incidents</span>
            <span className="text-2xl font-black text-red-400 tracking-tight mt-1">{activeThreatsCount}</span>
          </div>
          <div className="p-3 bg-red-500/10 text-red-400 rounded-xl border border-red-500/10">
            <Flame className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex justify-between items-center shadow-lg" id="stat-isolated-hosts">
          <div className="flex flex-col">
            <span className="text-[10px] font-bold text-slate-500 uppercase">Isolated Endpoints</span>
            <span className="text-2xl font-black text-amber-400 tracking-tight mt-1">{isolatedHostsCount}</span>
          </div>
          <div className="p-3 bg-amber-500/10 text-amber-400 rounded-xl border border-amber-500/10">
            <Server className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex justify-between items-center shadow-lg" id="stat-blocked-ips">
          <div className="flex flex-col">
            <span className="text-[10px] font-bold text-slate-500 uppercase">IP Blocklist count</span>
            <span className="text-2xl font-black text-indigo-400 tracking-tight mt-1">{blockedIpsCount}</span>
          </div>
          <div className="p-3 bg-indigo-500/10 text-indigo-400 rounded-xl border border-indigo-500/10">
            <UserX className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex justify-between items-center shadow-lg" id="stat-open-tickets">
          <div className="flex flex-col">
            <span className="text-[10px] font-bold text-slate-500 uppercase">Open IT Tickets</span>
            <span className="text-2xl font-black text-slate-300 tracking-tight mt-1">{openTicketsCount}</span>
          </div>
          <div className="p-3 bg-slate-500/10 text-slate-400 rounded-xl border border-slate-500/10">
            <ClipboardList className="w-5 h-5" />
          </div>
        </div>
      </section>

      {/* Core Layout: 3-column architecture */}
      <main className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-12 gap-6 min-h-0 overflow-y-auto" id="dashboard-columns-grid">

        {/* Left Column (SPAN 4): PCAP csv Uplink / ML IDS Evaluator */}
        <div className="lg:col-span-4 h-full" id="left-column-telemetry">
          <NetworkParser
            activeIncident={activeIncident}
            onRunResponder={handleRunResponder}
            isLoading={isLoadingInvestigate}
            endpointsList={Object.keys(endpoints)}
          />
        </div>

        {/* Center Column (SPAN 4): Investigation findings, Mitre Map & Report Markdown */}
        <div className="lg:col-span-4 flex flex-col gap-5 h-full" id="center-column-forensics">

          {/* History selection */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-2.5" id="incident-history-panel">
            <span className="text-xs font-semibold text-slate-300">Incident Forensics History</span>

            <div className="flex flex-col gap-1.5 max-h-[140px] overflow-y-auto pr-1">
              {incidents.map((inc) => (
                <button
                  key={inc.id}
                  id={`history-item-${inc.id}`}
                  onClick={() => setActiveIncidentId(inc.id)}
                  className={`text-[11px] text-left p-2 rounded-lg border flex items-center justify-between transition-all ${activeIncidentId === inc.id
                    ? "bg-slate-950 border-indigo-500 text-indigo-300"
                    : "bg-slate-950/40 border-slate-800/80 text-slate-400 hover:bg-slate-950/60"
                    }`}
                >
                  <div className="flex items-center gap-1.5 truncate max-w-[200px]">
                    <span className="font-mono font-bold">{inc.id}</span>
                    <span className="text-slate-600">|</span>
                    <span className="truncate">{inc.attack_type}</span>
                  </div>
                  <span className={`text-[9px] font-bold px-1 py-0.5 rounded ${inc.status === "Mitigated" ? "bg-emerald-500/10 text-emerald-400" : "bg-orange-500/10 text-orange-400"
                    }`}>
                    {inc.status}
                  </span>
                </button>
              ))}
            </div>
          </div>

          <div className="flex-1 min-h-0" id="center-investigation-pane">
            <InvestigationPanel
              activeIncident={activeIncident}
              onOpenTicket={handleOpenTicket}
              isOpeningTicket={isOpeningTicket}
            />
          </div>
        </div>

        {/* Right Column (SPAN 4): Actions Panel & Live Endpoint Console */}
        <div className="lg:col-span-4 flex flex-col gap-5 h-full" id="right-column-containment">

          {/* Containment Response Planner */}
          {activeIncident && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-2xl flex flex-col gap-3.5" id="containment-actions-panel">
              <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                <div>
                  <h2 className="text-xs font-bold text-white uppercase tracking-wider">Containment Response Planner</h2>
                  <p className="text-[10px] text-slate-400 mt-0.5">Approve or reject automated containment rules</p>
                </div>
                <span className="text-[9px] bg-red-500/10 text-red-400 px-1.5 py-0.5 rounded font-bold font-mono">SOAR Policy</span>
              </div>

              <div className="flex flex-col gap-2.5">
                {activeIncident.response_plan.map((act, index) => (
                  <div key={index} className="bg-slate-950 border border-slate-850 rounded-xl p-3 flex flex-col gap-2" id={`action-card-${index}`}>
                    <div className="flex justify-between items-start">
                      <span className="text-[10px] font-bold text-slate-300 uppercase tracking-wide flex items-center gap-1.5">
                        <span className={`w-1.5 h-1.5 rounded-full ${act.status === "Approved" ? "bg-emerald-400" : "bg-amber-400 animate-pulse"
                          }`} />
                        {act.type.replace('_', ' ')}: <span className="font-mono text-indigo-400">{act.target}</span>
                      </span>
                      <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${act.status === "Approved" ? "bg-emerald-500/10 text-emerald-400" :
                        act.status === "Executing" ? "bg-indigo-500/15 text-indigo-400 animate-pulse" :
                          "bg-amber-500/10 text-amber-400"
                        }`}>
                        {act.status}
                      </span>
                    </div>

                    <p className="text-[10px] text-slate-400 leading-relaxed">{act.description}</p>

                    {act.status === "Pending" && (
                      <div className="flex gap-2 mt-1">
                        <button
                          id={`approve-btn-${index}`}
                          onClick={() => handleExecuteAction(act.type, act.target)}
                          disabled={actionExecutingType !== null}
                          className="flex-1 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-bold text-[10px] py-1.5 px-2.5 rounded-lg shadow-md transition-all flex items-center justify-center gap-1"
                        >
                          <CheckCircle className="w-3 h-3" /> Approve & Execute
                        </button>
                        <button
                          id={`reject-btn-${index}`}
                          onClick={async () => {
                            // Local reject action
                            act.status = "Rejected";
                            triggerBanner("Containment action rejected and dismissed.");
                          }}
                          disabled={actionExecutingType !== null}
                          className="bg-slate-850 hover:bg-slate-800 text-slate-400 hover:text-white font-semibold text-[10px] py-1.5 px-2.5 rounded-lg border border-slate-800 transition-all"
                        >
                          Reject
                        </button>
                      </div>
                    )}

                    {act.status === "Executing" && (
                      <div className="flex items-center gap-2 text-[10px] text-indigo-400 font-bold bg-slate-900/60 p-2 rounded-lg border border-indigo-900/20">
                        <RefreshCw className="w-3 h-3 animate-spin" />
                        <span>SSH controller executing sandboxing rule on target host...</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Active Endpoint Console */}
          <div className="flex-1 min-h-[360px]" id="right-console-pane">
            <EndpointConsole
              endpoints={endpoints}
              selectedHostname={selectedConsoleHost}
              onSelectHost={setSelectedConsoleHost}
              onKillProcess={handleKillProcess}
              actionRunningPid={actionRunningPid}
            />
          </div>

          {/* Enforcement Engine Status */}
          <div id="firewall-status-pane">
            <FirewallStatus
              mode={firewallMode}
              paramikoAvailable={paramikoAvailable}
              winrmAvailable={winrmAvailable}
              blockedIps={blocklist}
              isolatedHosts={isolatedHosts}
              onUnblock={handleUnblock}
              onUnisolate={handleUnisolate}
            />
          </div>

        </div>
      </main>
    </div>
  );
}
