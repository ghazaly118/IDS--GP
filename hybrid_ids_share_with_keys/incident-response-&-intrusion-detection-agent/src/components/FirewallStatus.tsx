import React, { useState } from "react";
import {
  Shield,
  ShieldOff,
  Wifi,
  WifiOff,
  X,
  RefreshCw,
  Info,
  Terminal,
} from "lucide-react";

interface FirewallStatusProps {
  mode: string;
  paramikoAvailable: boolean;
  winrmAvailable: boolean;
  blockedIps: string[];
  isolatedHosts: string[];
  onUnblock: (ip: string) => Promise<void>;
  onUnisolate: (host: string) => Promise<void>;
}

const MODE_CONFIG: Record<string, { label: string; ring: string; dot: string; text: string }> = {
  demo: {
    label: "DEMO MODE",
    ring: "border-slate-700 bg-slate-800/60",
    dot: "bg-slate-400",
    text: "text-slate-400",
  },
  ssh_linux: {
    label: "SSH · LINUX",
    ring: "border-emerald-800 bg-emerald-950/60",
    dot: "bg-emerald-400 animate-pulse",
    text: "text-emerald-400",
  },
  windows_remote: {
    label: "WINRM · WINDOWS",
    ring: "border-blue-800 bg-blue-950/60",
    dot: "bg-blue-400 animate-pulse",
    text: "text-blue-400",
  },
  auto: {
    label: "AUTO DETECT",
    ring: "border-indigo-800 bg-indigo-950/60",
    dot: "bg-indigo-400 animate-pulse",
    text: "text-indigo-400",
  },
};

export default function FirewallStatus({
  mode,
  paramikoAvailable,
  winrmAvailable,
  blockedIps,
  isolatedHosts,
  onUnblock,
  onUnisolate,
}: FirewallStatusProps) {
  const [unblockingIp, setUnblockingIp] = useState<string | null>(null);
  const [unisolatingHost, setUnisolatingHost] = useState<string | null>(null);

  const cfg = MODE_CONFIG[mode] ?? {
    label: mode.toUpperCase(),
    ring: "border-slate-700 bg-slate-800/60",
    dot: "bg-slate-400",
    text: "text-slate-400",
  };

  const handleUnblock = async (ip: string) => {
    setUnblockingIp(ip);
    try { await onUnblock(ip); } finally { setUnblockingIp(null); }
  };

  const handleUnisolate = async (host: string) => {
    setUnisolatingHost(host);
    try { await onUnisolate(host); } finally { setUnisolatingHost(null); }
  };

  return (
    <div
      className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-3 shadow-xl"
      id="firewall-enforcement-panel"
    >
      {/* ── Header ── */}
      <div className="flex justify-between items-center border-b border-slate-800 pb-2.5">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-indigo-400" />
          <span className="text-[11px] font-bold text-white uppercase tracking-widest">
            Enforcement Engine
          </span>
        </div>
        <span
          className={`flex items-center gap-1.5 text-[9px] font-bold px-2 py-0.5 rounded-full border ${cfg.ring} ${cfg.text}`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
          {cfg.label}
        </span>
      </div>

      {/* ── Dependency badges ── */}
      <div className="grid grid-cols-2 gap-2">
        {[
          { label: "paramiko", ok: paramikoAvailable, hint: "SSH · Linux" },
          { label: "pywinrm",  ok: winrmAvailable,    hint: "WinRM · Windows" },
        ].map(({ label, ok, hint }) => (
          <div
            key={label}
            className={`flex items-center gap-1.5 text-[10px] px-2.5 py-1.5 rounded-lg border transition-all ${
              ok
                ? "bg-emerald-950/30 border-emerald-900/40 text-emerald-400"
                : "bg-slate-950 border-slate-800 text-slate-500"
            }`}
          >
            {ok ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
            <span className="font-mono font-bold">{label}</span>
            <span className={`ml-auto text-[8px] ${ok ? "text-emerald-600" : "text-slate-600"}`}>{hint}</span>
          </div>
        ))}
      </div>

      {/* ── Demo mode notice ── */}
      {mode === "demo" && (
        <div className="flex gap-2 bg-slate-950/80 border border-slate-800 rounded-lg p-2.5">
          <Info className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
          <p className="text-[10px] text-slate-400 leading-relaxed">
            <span className="text-amber-400 font-bold">Demo mode.</span> Rules are simulated
            &amp; logged to files only. Set{" "}
            <code className="text-indigo-400 bg-slate-900 px-1 rounded">ENFORCEMENT_MODE=ssh_linux</code>{" "}
            or{" "}
            <code className="text-indigo-400 bg-slate-900 px-1 rounded">windows_remote</code>{" "}
            in <code className="text-slate-300">.env</code> to activate real remote enforcement.
          </p>
        </div>
      )}

      {/* ── Blocked IPs ── */}
      <div className="flex flex-col gap-1.5">
        <div className="flex items-center gap-1.5">
          <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider">
            Blocked IPs
          </span>
          <span className="text-[9px] bg-slate-800 text-slate-400 font-mono px-1.5 py-0.5 rounded-full">
            {blockedIps.length}
          </span>
        </div>

        {blockedIps.length === 0 ? (
          <p className="text-[10px] text-slate-600 italic px-1">No IPs blocked yet.</p>
        ) : (
          <div className="flex flex-col gap-1 max-h-[110px] overflow-y-auto pr-0.5">
            {blockedIps.map((ip) => (
              <div
                key={ip}
                className="flex items-center justify-between bg-slate-950 border border-red-950/40 rounded-lg px-2.5 py-1.5 group hover:border-red-800/40 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0" />
                  <span className="text-[11px] font-mono text-red-300">{ip}</span>
                </div>
                <button
                  id={`unblock-btn-${ip.replace(/\./g, "-")}`}
                  onClick={() => handleUnblock(ip)}
                  disabled={!!unblockingIp}
                  className="flex items-center gap-1 text-[9px] font-bold text-slate-500 hover:text-white bg-slate-800/60 hover:bg-red-900/30 border border-slate-700 hover:border-red-800/40 px-1.5 py-0.5 rounded transition-all disabled:opacity-40"
                >
                  {unblockingIp === ip
                    ? <RefreshCw className="w-2.5 h-2.5 animate-spin" />
                    : <X className="w-2.5 h-2.5" />
                  }
                  Unblock
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Isolated Hosts ── */}
      <div className="flex flex-col gap-1.5">
        <div className="flex items-center gap-1.5">
          <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider">
            Isolated Hosts
          </span>
          <span className="text-[9px] bg-slate-800 text-slate-400 font-mono px-1.5 py-0.5 rounded-full">
            {isolatedHosts.length}
          </span>
        </div>

        {isolatedHosts.length === 0 ? (
          <p className="text-[10px] text-slate-600 italic px-1">No hosts isolated.</p>
        ) : (
          <div className="flex flex-col gap-1 max-h-[90px] overflow-y-auto pr-0.5">
            {isolatedHosts.map((host) => (
              <div
                key={host}
                className="flex items-center justify-between bg-slate-950 border border-amber-950/40 rounded-lg px-2.5 py-1.5 group hover:border-amber-800/40 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse shrink-0" />
                  <span className="text-[11px] font-mono text-amber-300">{host}</span>
                </div>
                <button
                  id={`unisolate-btn-${host}`}
                  onClick={() => handleUnisolate(host)}
                  disabled={!!unisolatingHost}
                  className="flex items-center gap-1 text-[9px] font-bold text-slate-500 hover:text-white bg-slate-800/60 hover:bg-amber-900/30 border border-slate-700 hover:border-amber-800/40 px-1.5 py-0.5 rounded transition-all disabled:opacity-40"
                >
                  {unisolatingHost === host
                    ? <RefreshCw className="w-2.5 h-2.5 animate-spin" />
                    : <ShieldOff className="w-2.5 h-2.5" />
                  }
                  Release
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Quick config hint (non-demo modes) ── */}
      {mode !== "demo" && (
        <div className="flex items-start gap-2 bg-slate-950/60 border border-slate-800/50 rounded-lg p-2">
          <Terminal className="w-3 h-3 text-slate-500 shrink-0 mt-0.5" />
          <p className="text-[9px] text-slate-500 font-mono leading-relaxed">
            IR Controller: <span className="text-slate-300">{/* shown in UI */}configured via IR_CONTROLLER_IP</span>
          </p>
        </div>
      )}
    </div>
  );
}
