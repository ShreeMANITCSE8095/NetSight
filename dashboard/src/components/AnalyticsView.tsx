import React, { useMemo } from 'react';
import { TopTrafficCard, TopBarItem, KpiCard } from './ReusableCards';
import { FlowRecord } from './FlowsView';
import { Finding, SummaryMetrics } from '../types';
import { ShieldAlert, CheckCircle2, Fingerprint, Radar } from 'lucide-react';
import { formatBytes } from '../utils';

interface AnalyticsViewProps {
  topApps: TopBarItem[];
  topDomains: TopBarItem[];
  flows: FlowRecord[];
  findings: Finding[];
  summaryMeta: Partial<SummaryMetrics>;
  onAcknowledgeFinding: (id: string) => void;
}

export const AnalyticsView: React.FC<AnalyticsViewProps> = ({
  topApps,
  topDomains,
  flows,
  findings,
  summaryMeta,
  onAcknowledgeFinding,
}) => {
  // Aggregate JA3 Client Fingerprints from active flows
  const ja3Items = useMemo(() => {
    const map = new Map<string, { hash: string; app: string; sni: string; count: number; bytes: number }>();
    for (const f of flows) {
      if (!f.ja3_hash) continue;
      const existing = map.get(f.ja3_hash);
      if (existing) {
        existing.count += 1;
        existing.bytes += f.total_bytes;
      } else {
        map.set(f.ja3_hash, {
          hash: f.ja3_hash,
          app: f.app || 'TLS',
          sni: f.sni || '—',
          count: 1,
          bytes: f.total_bytes,
        });
      }
    }
    return Array.from(map.values()).sort((a, b) => b.bytes - a.bytes).slice(0, 8);
  }, [flows]);

  // Extract DNS Entropy & Host Fan-out highlights
  const dnsAndScanFlows = useMemo(() => {
    return flows
      .filter(
        (f) =>
          (f.dns_entropy !== undefined && f.dns_entropy > 0) ||
          (f.src_distinct_dst_ports !== undefined && f.src_distinct_dst_ports >= 5)
      )
      .sort((a, b) => (b.dns_entropy || 0) - (a.dns_entropy || 0))
      .slice(0, 8);
  }, [flows]);

  return (
    <div className="flex flex-col gap-4">
      {/* Row 1: Deep DPI Summary KPIs */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <KpiCard
          title="Top Classified App"
          value={summaryMeta.top_app || 'None'}
          subtitle="Dominant L7 Protocol"
          deltaPercent={0}
        />
        <KpiCard
          title="Unlabeled Traffic Share"
          value={`${(summaryMeta.unlabeled_percent ?? 0).toFixed(1)}%`}
          subtitle="Encrypted without SNI / Generic"
          deltaPercent={0}
        />
        <KpiCard
          title="Security Findings"
          value={String(findings.filter((f) => !f.acknowledged).length)}
          subtitle="Unacknowledged Detections"
          deltaPercent={0}
        />
        <KpiCard
          title="Total Flows Tracked"
          value={(summaryMeta.total_flows ?? flows.length).toLocaleString()}
          subtitle={`Mode: ${(summaryMeta.mode || 'live').toUpperCase()}`}
          deltaPercent={0}
        />
      </div>

      {/* Row 2: Top Applications & Top Domains */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <TopTrafficCard
          title="Top Applications (L7 DPI)"
          subtitle="Classified application protocols by traffic volume"
          items={topApps}
          emptyMessage="No L7 application signatures classified yet"
        />
        <TopTrafficCard
          title="Top TLS SNI & DNS Domains"
          subtitle="Extracted server hostnames by traffic volume"
          items={topDomains}
          emptyMessage="No TLS ClientHello SNI or DNS queries observed yet"
        />
      </div>

      {/* Row 3: JA3 Cryptographic Fingerprints + DNS Entropy & Host Recon */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-xl bg-surface border border-subtle p-5 flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <Fingerprint className="w-4 h-4 text-[#4F46E5]" />
            <div>
              <h3 className="text-sm font-semibold text-primary">
                TLS JA3 Client Fingerprints
              </h3>
              <p className="text-xs text-secondary">
                MD5 hashes of TLS ClientHello cipher suites & extensions
              </p>
            </div>
          </div>

          {ja3Items.length === 0 ? (
            <div className="py-10 text-center text-xs text-secondary">
              No TLS ClientHello JA3 fingerprints captured yet.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b border-subtle text-secondary text-left">
                    <th className="py-2 pr-2">JA3 MD5 Hash</th>
                    <th className="py-2 px-2">Primary App / SNI</th>
                    <th className="py-2 px-2 text-right">Flows</th>
                    <th className="py-2 pl-2 text-right">Volume</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-subtle/60">
                  {ja3Items.map((item) => (
                    <tr key={item.hash} className="tabular-nums">
                      <td className="py-2 pr-2 font-mono text-[11px] text-primary">
                        {item.hash.slice(0, 16)}…
                      </td>
                      <td className="py-2 px-2 text-primary">
                        <span className="font-medium">{item.app}</span>{' '}
                        <span className="text-secondary font-mono text-[11px]">
                          ({item.sni})
                        </span>
                      </td>
                      <td className="py-2 px-2 text-right font-mono text-primary">
                        {item.count}
                      </td>
                      <td className="py-2 pl-2 text-right font-medium text-primary">
                        {formatBytes(item.bytes)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* DNS Shannon Entropy & Host Recon Fan-out */}
        <div className="rounded-xl bg-surface border border-subtle p-5 flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <Radar className="w-4 h-4 text-[#4F46E5]" />
            <div>
              <h3 className="text-sm font-semibold text-primary">
                DNS Shannon Entropy & Host Recon Fan-Out
              </h3>
              <p className="text-xs text-secondary">
                DGA / tunneling entropy heuristics (threshold 3.8 bits) & scanner profiling
              </p>
            </div>
          </div>

          {dnsAndScanFlows.length === 0 ? (
            <div className="py-10 text-center text-xs text-secondary">
              No DNS query entropy or elevated host fan-out recorded yet.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b border-subtle text-secondary text-left">
                    <th className="py-2 pr-2">Query / Host</th>
                    <th className="py-2 px-2 text-right">DNS Entropy</th>
                    <th className="py-2 px-2 text-right">Dst IPs</th>
                    <th className="py-2 pl-2 text-right">Dst Ports</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-subtle/60">
                  {dnsAndScanFlows.map((f) => (
                    <tr key={f.id} className="tabular-nums">
                      <td className="py-2 pr-2 font-mono text-[11px] text-primary truncate max-w-[180px]">
                        {f.dns_query || f.sni || f.src_ip}
                      </td>
                      <td
                        className={`py-2 px-2 text-right font-mono font-semibold ${
                          (f.dns_entropy || 0) >= 3.8 ? 'text-amber-500' : 'text-primary'
                        }`}
                      >
                        {(f.dns_entropy || 0).toFixed(2)} bits
                      </td>
                      <td className="py-2 px-2 text-right font-mono text-primary">
                        {f.src_distinct_dst_ips || 1}
                      </td>
                      <td className="py-2 pl-2 text-right font-mono text-primary">
                        {f.src_distinct_dst_ports || 1}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Row 4: Real-Time Security Findings & Anomaly Detections */}
      <div className="rounded-xl bg-surface border border-subtle p-5 flex flex-col gap-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-[#4F46E5]" />
          <div>
            <h3 className="text-sm font-semibold text-primary">
              Security Findings & Heuristic Detections
            </h3>
            <p className="text-xs text-secondary">
              Automated engine alerts across Port Scans, High-Entropy DNS, Asymmetric Uploads, and Firewall Rules
            </p>
          </div>
        </div>

        {findings.length === 0 ? (
          <div className="py-8 text-center text-xs text-secondary">
            No security anomalies or rule violations triggered.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs border-collapse">
              <thead>
                <tr className="border-b border-subtle text-secondary text-left">
                  <th className="py-2 pr-3">Severity</th>
                  <th className="py-2 px-3">Detector</th>
                  <th className="py-2 px-3">Finding & Details</th>
                  <th className="py-2 px-3">Endpoints</th>
                  <th className="py-2 pl-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-subtle/60">
                {findings.slice(0, 15).map((item) => (
                  <tr
                    key={item.id}
                    className={item.acknowledged ? 'opacity-50' : ''}
                  >
                    <td className="py-2.5 pr-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          item.severity === 'high'
                            ? 'bg-rose-500/15 text-rose-500'
                            : 'bg-amber-500/15 text-amber-500'
                        }`}
                      >
                        {item.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-secondary">
                      {item.detector}
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="font-semibold text-primary">{item.title}</div>
                      <div className="text-[11px] text-secondary">{item.details}</div>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-primary whitespace-nowrap">
                      {item.src} → {item.dst}
                    </td>
                    <td className="py-2.5 pl-3 text-right">
                      {item.acknowledged ? (
                        <span className="inline-flex items-center gap-1 text-[11px] text-emerald-500">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Acked
                        </span>
                      ) : (
                        <button
                          onClick={() => onAcknowledgeFinding(item.id)}
                          className="px-2.5 py-1 rounded bg-canvas border border-subtle hover:border-[#4F46E5] text-[11px] font-medium text-primary"
                        >
                          Acknowledge
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
