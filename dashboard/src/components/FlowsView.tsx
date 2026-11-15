import React, { useState, useMemo } from 'react';
import {
  ChevronsUpDown,
  X,
  ShieldAlert,
  Lock,
  Globe,
  Activity,
  Radar,
  Pause,
} from 'lucide-react';
import { formatBytes, formatBitrate, getAppColor } from '../utils';

export interface FlowRecord {
  id: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  total_bytes: number;
  live_bps: number;
  app?: string;
  sni?: string;
  ja3?: string;
  ja3_hash?: string;
  bytes_in?: number;
  bytes_out?: number;
  packets_in?: number;
  packets_out?: number;
  packets_total?: number;
  byte_ratio?: number;
  syn_count?: number;
  syn_ack_count?: number;
  fin_count?: number;
  rst_count?: number;
  tcp_flags?: string;
  dns_query?: string;
  dns_entropy?: number;
  dns_record_type?: number;
  src_distinct_dst_ips?: number;
  src_distinct_dst_ports?: number;
  state?: string;
  rule_match?: boolean;
  rule_reason?: string;
  duration_sec?: number;
}

type SortField =
  | 'src_ip'
  | 'dst_ip'
  | 'protocol'
  | 'app'
  | 'sni'
  | 'total_bytes'
  | 'live_bps';

type QuickFilter = 'all' | 'flagged' | 'unlabeled' | 'high_entropy' | 'upload_heavy';

export const FlowsView: React.FC<{ flows: FlowRecord[] }> = ({ flows }) => {
  const [sortField, setSortField] = useState<SortField>('live_bps');
  const [sortDesc, setSortDesc] = useState<boolean>(true);
  const [quickFilter, setQuickFilter] = useState<QuickFilter>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isHovered, setIsHovered] = useState<boolean>(false);
  const [selectedFlowId, setSelectedFlowId] = useState<string | null>(null);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDesc((prev) => !prev);
    } else {
      setSortField(field);
      setSortDesc(true);
    }
  };

  const frozenFlowsRef = React.useRef<FlowRecord[]>(flows);
  if (!isHovered) {
    frozenFlowsRef.current = flows;
  }
  const activeFlows = isHovered ? frozenFlowsRef.current : flows;

  const filteredFlows = useMemo(() => {
    return activeFlows.filter((f) => {
      if (quickFilter === 'flagged' && !f.rule_match) return false;
      if (
        quickFilter === 'unlabeled' &&
        f.app &&
        !['UNKNOWN', 'Unlabeled', 'HTTPS', 'HTTP'].includes(f.app)
      )
        return false;
      if (quickFilter === 'high_entropy' && (f.dns_entropy || 0) < 3.5) return false;
      if (quickFilter === 'upload_heavy' && (f.byte_ratio || 0) < 2.0) return false;

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const match =
          f.src_ip.toLowerCase().includes(q) ||
          f.dst_ip.toLowerCase().includes(q) ||
          (f.app || '').toLowerCase().includes(q) ||
          (f.sni || '').toLowerCase().includes(q) ||
          (f.ja3_hash || '').toLowerCase().includes(q);
        if (!match) return false;
      }
      return true;
    });
  }, [activeFlows, quickFilter, searchQuery]);

  const sortedFlows = useMemo(() => {
    const copy = [...filteredFlows];
    copy.sort((a, b) => {
      const valA = a[sortField] ?? '';
      const valB = b[sortField] ?? '';
      if (typeof valA === 'number' && typeof valB === 'number') {
        return sortDesc ? valB - valA : valA - valB;
      }
      return sortDesc
        ? String(valB).localeCompare(String(valA))
        : String(valA).localeCompare(String(valB));
    });
    return copy;
  }, [filteredFlows, sortField, sortDesc]);

  const selectedFlow = useMemo(
    () => flows.find((f) => f.id === selectedFlowId) || null,
    [flows, selectedFlowId]
  );

  return (
    <div className="flex flex-col gap-3 relative">
      {/* Top Filter & Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          {(
            [
              { id: 'all', label: `All Flows (${flows.length})` },
              { id: 'flagged', label: 'Rule Alerts' },
              { id: 'unlabeled', label: 'Generic / Unlabeled' },
              { id: 'high_entropy', label: 'High DNS Entropy' },
              { id: 'upload_heavy', label: 'High Upload Ratio' },
            ] as { id: QuickFilter; label: string }[]
          ).map((chip) => (
            <button
              key={chip.id}
              onClick={() => setQuickFilter(chip.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                quickFilter === chip.id
                  ? 'bg-[#4F46E5] text-white border-[#4F46E5]'
                  : 'bg-surface text-secondary border-subtle hover:text-primary'
              }`}
            >
              {chip.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          {isHovered && (
            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-amber-500/10 text-amber-500 text-[11px] font-medium">
              <Pause className="w-3 h-3" /> Sort Paused (Hover)
            </span>
          )}
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter IP, App, SNI, JA3..."
            className="h-8 px-3 rounded-lg bg-surface border border-subtle text-xs text-primary placeholder:text-secondary focus:outline-none focus:border-[#4F46E5] w-56"
          />
        </div>
      </div>

      {/* Main Connections Table */}
      <div className="w-full overflow-x-auto rounded-xl bg-surface border border-subtle">
        <table className="w-full border-collapse text-xs">
          <thead>
            <tr className="border-b border-subtle text-secondary">
              <th className="py-3 px-3 font-semibold text-left">
                <button
                  onClick={() => handleSort('src_ip')}
                  className="inline-flex items-center gap-1 hover:text-primary"
                >
                  <span>Source</span>
                  <ChevronsUpDown className="w-3.5 h-3.5 opacity-70" />
                </button>
              </th>
              <th className="py-3 px-3 font-semibold text-left">
                <button
                  onClick={() => handleSort('dst_ip')}
                  className="inline-flex items-center gap-1 hover:text-primary"
                >
                  <span>Destination</span>
                  <ChevronsUpDown className="w-3.5 h-3.5 opacity-70" />
                </button>
              </th>
              <th className="py-3 px-3 font-semibold text-center">
                <button
                  onClick={() => handleSort('protocol')}
                  className="inline-flex items-center gap-1 hover:text-primary"
                >
                  <span>Proto</span>
                  <ChevronsUpDown className="w-3.5 h-3.5 opacity-70" />
                </button>
              </th>
              <th className="py-3 px-3 font-semibold text-left">
                <button
                  onClick={() => handleSort('app')}
                  className="inline-flex items-center gap-1 hover:text-primary"
                >
                  <span>Application (L7)</span>
                  <ChevronsUpDown className="w-3.5 h-3.5 opacity-70" />
                </button>
              </th>
              <th className="py-3 px-3 font-semibold text-left">
                <button
                  onClick={() => handleSort('sni')}
                  className="inline-flex items-center gap-1 hover:text-primary"
                >
                  <span>TLS SNI / DNS Host</span>
                  <ChevronsUpDown className="w-3.5 h-3.5 opacity-70" />
                </button>
              </th>
              <th className="py-3 px-3 font-semibold text-right">
                <button
                  onClick={() => handleSort('total_bytes')}
                  className="inline-flex items-center gap-1 hover:text-primary"
                >
                  <span>Volume</span>
                  <ChevronsUpDown className="w-3.5 h-3.5 opacity-70" />
                </button>
              </th>
              <th className="py-3 px-3 font-semibold text-right">
                <button
                  onClick={() => handleSort('live_bps')}
                  className="inline-flex items-center gap-1 hover:text-primary"
                >
                  <span>Live Speed</span>
                  <ChevronsUpDown className="w-3.5 h-3.5 opacity-70" />
                </button>
              </th>
            </tr>
          </thead>
          <tbody
            className="divide-y divide-subtle/70"
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
          >
            {sortedFlows.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-xs text-secondary">
                  No matching flows. Click a filter above or wait for telemetry.
                </td>
              </tr>
            ) : (
              sortedFlows.map((flow) => {
                const isSelected = flow.id === selectedFlowId;
                return (
                  <tr
                    key={flow.id}
                    onClick={() => setSelectedFlowId(flow.id)}
                    className={`cursor-pointer transition-colors tabular-nums ${
                      isSelected
                        ? 'bg-[#4F46E5]/10'
                        : flow.rule_match
                        ? 'bg-rose-500/5 hover:bg-rose-500/10'
                        : 'hover:bg-black/[0.02] dark:hover:bg-white/[0.02]'
                    }`}
                  >
                    <td className="py-3 px-3 font-mono text-primary whitespace-nowrap">
                      {flow.src_ip}:{flow.src_port}
                    </td>
                    <td className="py-3 px-3 font-mono text-primary whitespace-nowrap">
                      {flow.dst_ip}:{flow.dst_port}
                    </td>
                    <td className="py-3 px-3 font-medium text-center text-primary">
                      {flow.protocol}
                    </td>
                    <td className="py-3 px-3 text-primary">
                      <span className="inline-flex items-center gap-1.5 font-medium">
                        <span
                          className="w-2 h-2 rounded-full flex-shrink-0"
                          style={{ backgroundColor: getAppColor(flow.app || 'UNKNOWN') }}
                        />
                        <span>{flow.app || 'UNKNOWN'}</span>
                        {flow.rule_match && (
                          <span className="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-500 text-[10px] font-semibold">
                            ALERT
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono text-secondary truncate max-w-[220px]">
                      {flow.sni || flow.dns_query || '—'}
                    </td>
                    <td className="py-3 px-3 text-right font-medium text-primary whitespace-nowrap">
                      {formatBytes(flow.total_bytes, 2)}
                    </td>
                    <td className="py-3 px-3 text-right font-medium text-primary whitespace-nowrap">
                      {formatBitrate(flow.live_bps)}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Deep DPI Flow Inspector Slide-Over Drawer */}
      {selectedFlow && (
        <div className="fixed inset-y-0 right-0 z-40 w-full max-w-md bg-surface border-l border-subtle shadow-2xl p-5 overflow-y-auto flex flex-col gap-4">
          <div className="flex items-center justify-between border-b border-subtle pb-3">
            <div>
              <h3 className="text-sm font-bold text-primary">
                Deep Flow Telemetry Inspector
              </h3>
              <p className="text-[11px] font-mono text-secondary mt-0.5">
                {selectedFlow.src_ip}:{selectedFlow.src_port} → {selectedFlow.dst_ip}:
                {selectedFlow.dst_port} ({selectedFlow.protocol})
              </p>
            </div>
            <button
              onClick={() => setSelectedFlowId(null)}
              className="p-1.5 rounded-lg text-secondary hover:text-primary hover:bg-black/5 dark:hover:bg-white/5"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {selectedFlow.rule_match && (
            <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-500 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 flex-shrink-0" />
              <div>
                <div className="font-semibold">Firewall Rule Match</div>
                <div className="text-[11px]">{selectedFlow.rule_reason}</div>
              </div>
            </div>
          )}

          {/* Classification & Hostname */}
          <div className="rounded-lg bg-canvas border border-subtle p-3.5 space-y-2 text-xs">
            <div className="flex items-center gap-1.5 font-semibold text-primary">
              <Globe className="w-3.5 h-3.5 text-[#4F46E5]" />
              <span>L7 Classification & Identity</span>
            </div>
            <div className="grid grid-cols-2 gap-2 pt-1">
              <div>
                <div className="text-[11px] text-secondary">Detected Application</div>
                <div className="font-semibold text-primary">
                  {selectedFlow.app || 'Unlabeled'}
                </div>
              </div>
              <div>
                <div className="text-[11px] text-secondary">Flow State / Duration</div>
                <div className="font-mono text-primary">
                  {(selectedFlow.state || 'active').toUpperCase()} ·{' '}
                  {(selectedFlow.duration_sec || 0).toFixed(1)}s
                </div>
              </div>
              <div className="col-span-2">
                <div className="text-[11px] text-secondary">Extracted TLS SNI / HTTP Host</div>
                <div className="font-mono text-primary break-all">
                  {selectedFlow.sni || 'None (No cleartext SNI)'}
                </div>
              </div>
            </div>
          </div>

          {/* Directional Volume & Asymmetry */}
          <div className="rounded-lg bg-canvas border border-subtle p-3.5 space-y-2 text-xs">
            <div className="flex items-center gap-1.5 font-semibold text-primary">
              <Activity className="w-3.5 h-3.5 text-[#4F46E5]" />
              <span>Directional Volume & Asymmetry</span>
            </div>
            <div className="grid grid-cols-3 gap-2 pt-1 tabular-nums">
              <div>
                <div className="text-[11px] text-secondary">Outbound (Client)</div>
                <div className="font-semibold text-primary">
                  {formatBytes(selectedFlow.bytes_out || 0)}
                </div>
                <div className="text-[10px] text-secondary">
                  {selectedFlow.packets_out || 0} pkts
                </div>
              </div>
              <div>
                <div className="text-[11px] text-secondary">Inbound (Server)</div>
                <div className="font-semibold text-primary">
                  {formatBytes(selectedFlow.bytes_in || 0)}
                </div>
                <div className="text-[10px] text-secondary">
                  {selectedFlow.packets_in || 0} pkts
                </div>
              </div>
              <div>
                <div className="text-[11px] text-secondary">Out/In Byte Ratio</div>
                <div className="font-mono font-semibold text-primary">
                  {(selectedFlow.byte_ratio || 0).toFixed(2)}x
                </div>
              </div>
            </div>
          </div>

          {/* TCP Handshake & Flag Counters */}
          <div className="rounded-lg bg-canvas border border-subtle p-3.5 space-y-2 text-xs">
            <div className="font-semibold text-primary">
              TCP State & Flag Telemetry ({selectedFlow.tcp_flags || 'NONE'})
            </div>
            <div className="grid grid-cols-4 gap-2 pt-1 text-center font-mono">
              <div className="p-2 rounded bg-surface border border-subtle">
                <div className="text-[10px] text-secondary">SYN</div>
                <div className="font-bold text-primary">{selectedFlow.syn_count || 0}</div>
              </div>
              <div className="p-2 rounded bg-surface border border-subtle">
                <div className="text-[10px] text-secondary">SYN-ACK</div>
                <div className="font-bold text-primary">
                  {selectedFlow.syn_ack_count || 0}
                </div>
              </div>
              <div className="p-2 rounded bg-surface border border-subtle">
                <div className="text-[10px] text-secondary">FIN</div>
                <div className="font-bold text-primary">{selectedFlow.fin_count || 0}</div>
              </div>
              <div className="p-2 rounded bg-surface border border-subtle">
                <div className="text-[10px] text-secondary">RST</div>
                <div className="font-bold text-rose-500">{selectedFlow.rst_count || 0}</div>
              </div>
            </div>
          </div>

          {/* TLS JA3 Fingerprint */}
          <div className="rounded-lg bg-canvas border border-subtle p-3.5 space-y-2 text-xs">
            <div className="flex items-center gap-1.5 font-semibold text-primary">
              <Lock className="w-3.5 h-3.5 text-[#4F46E5]" />
              <span>TLS ClientHello JA3 Fingerprint</span>
            </div>
            <div>
              <div className="text-[11px] text-secondary">JA3 MD5 Hash</div>
              <div className="font-mono text-primary break-all">
                {selectedFlow.ja3_hash || '—'}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-secondary">Raw JA3 String</div>
              <div className="font-mono text-[11px] text-secondary break-all max-h-20 overflow-y-auto">
                {selectedFlow.ja3 || '—'}
              </div>
            </div>
          </div>

          {/* DNS Entropy & Host Reconnaissance */}
          <div className="rounded-lg bg-canvas border border-subtle p-3.5 space-y-2 text-xs">
            <div className="flex items-center gap-1.5 font-semibold text-primary">
              <Radar className="w-3.5 h-3.5 text-[#4F46E5]" />
              <span>DNS Heuristics & Host Fan-Out</span>
            </div>
            <div className="grid grid-cols-2 gap-2 pt-1">
              <div>
                <div className="text-[11px] text-secondary">DNS Shannon Entropy</div>
                <div
                  className={`font-mono font-semibold ${
                    (selectedFlow.dns_entropy || 0) >= 3.8
                      ? 'text-amber-500'
                      : 'text-primary'
                  }`}
                >
                  {(selectedFlow.dns_entropy || 0).toFixed(2)} bits/char
                </div>
              </div>
              <div>
                <div className="text-[11px] text-secondary">DNS Record Type</div>
                <div className="font-mono text-primary">
                  {selectedFlow.dns_record_type || '—'}
                </div>
              </div>
              <div>
                <div className="text-[11px] text-secondary">Host Distinct Dst IPs</div>
                <div className="font-mono font-semibold text-primary">
                  {selectedFlow.src_distinct_dst_ips || 0} hosts
                </div>
              </div>
              <div>
                <div className="text-[11px] text-secondary">Host Distinct Dst Ports</div>
                <div className="font-mono font-semibold text-primary">
                  {selectedFlow.src_distinct_dst_ports || 0} ports
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
