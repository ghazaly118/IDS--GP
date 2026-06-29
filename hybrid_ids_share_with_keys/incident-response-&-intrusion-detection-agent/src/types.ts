export interface FlowMetrics {
  src_ip?: string;
  dst_ip?: string;
  src_port?: string;
  dst_port?: string;
  protocol?: string;
  packets?: number;
  bytes?: number;
  duration?: number;
  flags?: string;
  label?: string;
}

export interface IDSFeatureImportance {
  feature: string;
  weight: number;
  value: any;
}

export interface IDSPrediction {
  label: string;
  confidence: number;
  isAnomalous: boolean;
}

export interface MitreMapping {
  id: string;
  name: string;
  tactic: string;
}

export interface ResponseAction {
  type: "isolate_host" | "block_ip" | "kill_process";
  target: string;
  description: string;
  status: "Pending" | "Approved" | "Executing" | "Rejected";
}

export interface Incident {
  id: string;
  timestamp: string;
  source_ip: string;
  target_ip: string;
  target_host: string;
  attack_type: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  cvss: number;
  cvss_vector?: string;
  mitre: MitreMapping;
  investigation_summary: string;
  response_plan: ResponseAction[];
  markdown_report?: string;
  status: "Investigated" | "Mitigated" | "Needs Action";
  traffic_stats?: {
    packets: number;
    bytes: number;
    duration_ms: number;
    protocol: string;
    service: string;
  };
}

export interface ITTicket {
  ticket_id: string;
  incident_id: string;
  title: string;
  status: "Open" | "In Progress" | "Closed";
  priority: "Low" | "Medium" | "High" | "Critical";
  assignee: string;
  created_at: string;
}

export interface Process {
  pid: number;
  name: string;
  cpu: number;
  memory: number;
  status: "Running" | "Suspicious" | "Defunct";
}

export interface FirewallRule {
  id: string;
  direction: "INBOUND" | "OUTBOUND";
  proto: string;
  port: string;
  action: "ALLOW" | "DENY";
  source: string;
  destination: string;
}

export interface EndpointAgent {
  hostname: string;
  ip: string;
  os: "Linux" | "Windows Server";
  status: "ONLINE" | "ISOLATED" | "OFFLINE";
  connectionsCount: number;
  processes: Process[];
  firewallRules: FirewallRule[];
  terminalLogs: string[];
}
