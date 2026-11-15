export interface FlowRecord {
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  proto: string;
  app: string;
  sni: string;
  bytes_total: number;
  packets_total: number;
  live_speed?: number;
  bytes_in: number;
  bytes_out: number;
  packets_in: number;
  packets_out: number;
  byte_ratio: number;
  syn_count: number;
  syn_ack_count: number;
  fin_count: number;
  rst_count: number;
  ja3: string;
  ja3_hash?: string;
  dns_entropy: number;
  dns_record_type: number | string;
  src_distinct_dst_ips: number;
  src_distinct_dst_ports: number;
  first_seen: number;
  last_seen: number;
  first_seen_iso?: string;
  last_seen_iso?: string;
  duration_sec?: number;
  state: string;
  rule_match: boolean;
  rule_reason: string;
  generation?: number;
}

export interface SummaryMetrics {
  current_bps: number;
  current_pps: number;
  active_flows: number;
  total_flows: number;
  total_bytes: number;
  top_app: string;
  top_domain: string;
  unlabeled_percent?: number;
  alert_count?: number;
  engine_connected: boolean;
  mode: 'live' | 'replay';
  drops?: number | null;
}

export interface AppBreakdown {
  app: string;
  bytes: number;
  packets: number;
  flows: number;
  share_percent: number;
}

export interface DomainBreakdown {
  domain: string;
  app: string;
  bytes: number;
  packets: number;
  flows: number;
  share_percent: number;
}

export interface HistoryPoint {
  minute: number;
  timestamp_iso?: string;
  total_bytes: number;
  total_packets: number;
  bps: number;
  pps: number;
  active_flows: number;
  app_breakdown: Record<string, number>;
}

export interface Finding {
  id: string;
  timestamp_iso: string;
  detector: 'rule' | 'port_scan' | 'high_entropy_dns' | 'upload_heavy';
  severity: 'high' | 'medium' | 'low';
  title: string;
  flow_id: string;
  src: string;
  dst: string;
  app: string;
  domain?: string | null;
  details: string;
  acknowledged: boolean;
}

export interface RatePoint {
  timestamp: number;
  bps: number;
  pps: number;
  active_flows: number;
}

export interface RulesPayload {
  block_apps: string[];
  block_domains: string[];
  block_ips: string[];
  block_ports: number[];
}

export interface HealthResponse {
  status: string;
  mode: string;
  engine_connected: boolean;
  uptime_sec: number;
  active_flows: number;
  binary_found: boolean;
}

export type ViewTab = 'overview' | 'traffic' | 'flows' | 'findings' | 'rules' | 'analyze';
