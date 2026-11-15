import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { HistoryRangePreset } from '../components/Navbar';
import { BandwidthPoint, OverviewProps } from '../components/OverviewView';
import { FlowRecord } from '../components/FlowsView';
import { HistoryPoint, HistoryViewProps } from '../components/HistoryView';
import { TopBarItem } from '../components/ReusableCards';
import { FirewallRules } from '../components/RulesView';
import { Finding, SummaryMetrics } from '../types';
import { calculateEmaDelta } from '../utils';

function createInitialRingBuffer(): BandwidthPoint[] {
  return Array.from({ length: 60 }, (_, i) => ({
    label: `${59 - i}s`,
    mbps: 0,
    bps: 0,
  }));
}

function rangeToMinutes(preset: HistoryRangePreset): number {
  switch (preset) {
    case '1h':
      return 60;
    case '6h':
      return 360;
    case '24h':
      return 1440;
    case '7d':
      return 10080;
    case '30d':
      return 43200;
    default:
      return 1440;
  }
}

function formatPresetDates(preset: HistoryRangePreset): { start: string; end: string } {
  const now = new Date();
  const mins = rangeToMinutes(preset);
  const start = new Date(now.getTime() - mins * 60 * 1000);

  const fmt = (d: Date) => {
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()} ${pad(
      d.getHours()
    )}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };

  return {
    start: fmt(start),
    end: fmt(now),
  };
}

export function useNetSightTelemetry(historyRange: HistoryRangePreset = '24h') {
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [liveBandwidthBps, setLiveBandwidthBps] = useState<number>(0);
  const [packetsPerSec, setPacketsPerSec] = useState<number>(0);
  const [avgPacketSizeBytes, setAvgPacketSizeBytes] = useState<number>(0);
  const [newConnectionsPerSec, setNewConnectionsPerSec] = useState<number>(0);
  const [summaryMeta, setSummaryMeta] = useState<Partial<SummaryMetrics>>({
    top_app: 'None',
    top_domain: 'None',
    unlabeled_percent: 0,
    alert_count: 0,
    total_flows: 0,
    total_bytes: 0,
    mode: 'replay',
    drops: null,
  });

  // EMA Deltas
  const [bandwidthDeltaPct, setBandwidthDeltaPct] = useState<number>(0);
  const [packetsDeltaPct, setPacketsDeltaPct] = useState<number>(0);
  const [packetSizeDeltaPct, setPacketSizeDeltaPct] = useState<number>(0);
  const [connectionsDeltaPct, setConnectionsDeltaPct] = useState<number>(0);

  const bwEmaRef = useRef<number>(0);
  const ppsEmaRef = useRef<number>(0);
  const sizeEmaRef = useRef<number>(0);
  const connEmaRef = useRef<number>(0);

  // Rolling Ring Buffer
  const [bandwidthSeries, setBandwidthSeries] = useState<BandwidthPoint[]>(createInitialRingBuffer);

  // Active Flows & Findings
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);

  // Analytics
  const [topApps, setTopApps] = useState<TopBarItem[]>([]);
  const [topDomains, setTopDomains] = useState<TopBarItem[]>([]);

  // History State
  const [isHistoryLoading, setIsHistoryLoading] = useState<boolean>(true);
  const [historySeries, setHistorySeries] = useState<HistoryPoint[]>([]);
  const [historyProtocols, setHistoryProtocols] = useState<{ name: string; value: number }[]>([]);
  const [historyApps, setHistoryApps] = useState<TopBarItem[]>([]);
  const [historyDomains, setHistoryDomains] = useState<TopBarItem[]>([]);

  // Firewall Rules
  const [rules, setRules] = useState<FirewallRules>({
    block_apps: [],
    block_ips: [],
    block_domains: [],
    block_ports: [],
  });

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const prevFlowBytesRef = useRef<Map<string, number>>(new Map());

  // Derive Top Talkers, Destinations, and Services from active flows
  const { topTalkers, topDestinations, topServices, liveProtocols } = useMemo(() => {
    const talkersMap = new Map<string, number>();
    const destMap = new Map<string, number>();
    const servicesMap = new Map<string, number>();
    const protoMap = new Map<string, number>();

    for (const f of flows) {
      const bytes = f.total_bytes || 0;
      talkersMap.set(f.src_ip, (talkersMap.get(f.src_ip) || 0) + bytes);
      destMap.set(f.dst_ip, (destMap.get(f.dst_ip) || 0) + bytes);
      const portKey = String(f.dst_port);
      servicesMap.set(portKey, (servicesMap.get(portKey) || 0) + bytes);
      const p = (f.protocol || 'TCP').toUpperCase();
      protoMap.set(p, (protoMap.get(p) || 0) + bytes);
    }

    const toSortedItems = (m: Map<string, number>): TopBarItem[] =>
      Array.from(m.entries())
        .map(([label, bytes]) => ({ label, bytes }))
        .sort((a, b) => b.bytes - a.bytes)
        .slice(0, 6);

    const protoList = Array.from(protoMap.entries()).map(([name, value]) => ({
      name,
      value,
    }));

    return {
      topTalkers: toSortedItems(talkersMap),
      topDestinations: toSortedItems(destMap),
      topServices: toSortedItems(servicesMap),
      liveProtocols: protoList.length > 0 ? protoList : [{ name: 'TCP', value: 1 }],
    };
  }, [flows]);

  const pushTelemetryTick = useCallback(
    (bps: number, pps: number, activeFlowCount: number, meta?: Partial<SummaryMetrics>) => {
      setLiveBandwidthBps(bps);
      setPacketsPerSec(pps);
      const avgSize = pps > 0 ? bps / 8 / pps : 0;
      setAvgPacketSizeBytes(avgSize);
      setNewConnectionsPerSec(activeFlowCount);
      if (meta) {
        setSummaryMeta((prev) => ({ ...prev, ...meta }));
      }

      const bwRes = calculateEmaDelta(bps, bwEmaRef.current);
      bwEmaRef.current = bwRes.nextEma;
      setBandwidthDeltaPct(bwRes.deltaPct);

      const ppsRes = calculateEmaDelta(pps, ppsEmaRef.current);
      ppsEmaRef.current = ppsRes.nextEma;
      setPacketsDeltaPct(ppsRes.deltaPct);

      const sizeRes = calculateEmaDelta(avgSize, sizeEmaRef.current);
      sizeEmaRef.current = sizeRes.nextEma;
      setPacketSizeDeltaPct(sizeRes.deltaPct);

      const connRes = calculateEmaDelta(activeFlowCount, connEmaRef.current);
      connEmaRef.current = connRes.nextEma;
      setConnectionsDeltaPct(connRes.deltaPct);

      setBandwidthSeries((prev) => {
        const next = prev.slice(1);
        next.push({
          label: '0s',
          bps,
          mbps: Number((bps / 1_000_000).toFixed(2)),
        });
        return next.map((pt, idx) => ({
          ...pt,
          label: `${59 - idx}s`,
        }));
      });
    },
    []
  );

  // Map raw API flow objects to full FlowRecord with all DPI fields preserved
  const processFlows = useCallback((rawFlows: any[]): FlowRecord[] => {
    const nextMap = new Map<string, number>();

    const mapped = rawFlows.map((f: any) => {
      const id = String(f.flow_id || `${f.src_ip}:${f.src_port}->${f.dst_ip}:${f.dst_port}`);
      const totalBytes = Number(f.total_bytes ?? f.bytes_total ?? 0);
      const prevBytes = prevFlowBytesRef.current.get(id);

      let liveBps = 0;
      if (f.live_speed !== undefined && f.live_speed !== null && Number(f.live_speed) > 0) {
        liveBps = Number(f.live_speed);
      } else if (prevBytes !== undefined && totalBytes > prevBytes) {
        liveBps = (totalBytes - prevBytes) * 8;
      }

      nextMap.set(id, totalBytes);

      return {
        id,
        src_ip: String(f.src_ip || '0.0.0.0'),
        src_port: Number(f.src_port || 0),
        dst_ip: String(f.dst_ip || '0.0.0.0'),
        dst_port: Number(f.dst_port || 0),
        protocol: String(f.proto || f.protocol || 'TCP').toUpperCase(),
        total_bytes: totalBytes,
        live_bps: liveBps,
        app: String(f.app || 'UNKNOWN'),
        sni: String(f.sni || ''),
        ja3: String(f.ja3 || ''),
        ja3_hash: String(f.ja3_hash || ''),
        bytes_in: Number(f.bytes_in || 0),
        bytes_out: Number(f.bytes_out || 0),
        packets_in: Number(f.packets_in || 0),
        packets_out: Number(f.packets_out || 0),
        packets_total: Number(f.packets_total || 0),
        byte_ratio: Number(f.byte_ratio || 0),
        syn_count: Number(f.syn_count || 0),
        syn_ack_count: Number(f.syn_ack_count || 0),
        fin_count: Number(f.fin_count || 0),
        rst_count: Number(f.rst_count || 0),
        tcp_flags: String(f.tcp_flags || ''),
        dns_query: String(f.dns_query || ''),
        dns_entropy: Number(f.dns_entropy || 0),
        dns_record_type: Number(f.dns_record_type || 0),
        src_distinct_dst_ips: Number(f.src_distinct_dst_ips || 0),
        src_distinct_dst_ports: Number(f.src_distinct_dst_ports || 0),
        state: String(f.state || 'active'),
        rule_match: Boolean(f.rule_match),
        rule_reason: String(f.rule_reason || ''),
        duration_sec: Number(f.duration_sec || (f.duration_ms ? f.duration_ms / 1000 : 0)),
      };
    });

    prevFlowBytesRef.current = nextMap;
    return mapped;
  }, []);

  const fetchRules = useCallback(async () => {
    try {
      const res = await fetch('/api/rules');
      if (res.ok) {
        const data = await res.json();
        setRules({
          block_apps: data.block_apps || [],
          block_ips: data.block_ips || [],
          block_domains: data.block_domains || [],
          block_ports: data.block_ports || [],
        });
      }
    } catch {
      // ignore
    }
  }, []);

  const addRule = useCallback(
    async (type: 'ip' | 'domain' | 'port', value: string) => {
      const updated: FirewallRules = {
        block_apps: rules.block_apps || [],
        block_ips: [...rules.block_ips],
        block_domains: [...rules.block_domains],
        block_ports: [...rules.block_ports],
      };

      if (type === 'ip' && !updated.block_ips.includes(value)) {
        updated.block_ips.push(value);
      } else if (type === 'domain' && !updated.block_domains.includes(value)) {
        updated.block_domains.push(value);
      } else if (type === 'port') {
        const p = parseInt(value, 10);
        if (!isNaN(p) && !updated.block_ports.includes(p)) {
          updated.block_ports.push(p);
        }
      }

      try {
        const res = await fetch('/api/rules', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            block_apps: updated.block_apps,
            block_domains: updated.block_domains,
            block_ips: updated.block_ips,
            block_ports: updated.block_ports,
          }),
        });
        if (res.ok) {
          setRules(updated);
        } else {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || `Failed to save rule (${res.status})`);
        }
      } catch (e) {
        console.error('Failed to add rule:', e);
        throw e;
      }
    },
    [rules]
  );

  const removeRule = useCallback(
    async (type: 'ip' | 'domain' | 'port', value: string | number) => {
      const updated: FirewallRules = {
        block_apps: rules.block_apps || [],
        block_ips: [...rules.block_ips],
        block_domains: [...rules.block_domains],
        block_ports: [...rules.block_ports],
      };

      if (type === 'ip') {
        updated.block_ips = updated.block_ips.filter((x) => x !== value);
      } else if (type === 'domain') {
        updated.block_domains = updated.block_domains.filter((x) => x !== value);
      } else if (type === 'port') {
        const p = Number(value);
        updated.block_ports = updated.block_ports.filter((x) => x !== p);
      }

      try {
        const res = await fetch('/api/rules', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            block_apps: updated.block_apps,
            block_domains: updated.block_domains,
            block_ips: updated.block_ips,
            block_ports: updated.block_ports,
          }),
        });
        if (res.ok) {
          setRules(updated);
        } else {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || `Failed to remove rule (${res.status})`);
        }
      } catch (e) {
        console.error('Failed to remove rule:', e);
        throw e;
      }
    },
    [rules]
  );

  const acknowledgeFinding = useCallback(async (findingId: string) => {
    try {
      const res = await fetch(`/api/findings/${encodeURIComponent(findingId)}/acknowledge`, {
        method: 'POST',
      });
      if (res.ok) {
        setFindings((prev) =>
          prev.map((f) => (f.id === findingId ? { ...f, acknowledged: true } : f))
        );
      }
    } catch {
      // ignore
    }
  }, []);

  const fetchAnalytics = useCallback(async () => {
    try {
      const [appsRes, domsRes, findingsRes] = await Promise.all([
        fetch('/api/apps'),
        fetch('/api/domains'),
        fetch('/api/findings'),
      ]);
      if (appsRes.ok) {
        const data = await appsRes.json();
        setTopApps(
          (data || []).map((a: any) => ({
            label: a.app || a.label || 'Unknown',
            bytes: a.bytes || a.total_bytes || 0,
          }))
        );
      }
      if (domsRes.ok) {
        const data = await domsRes.json();
        setTopDomains(
          (data || []).map((d: any) => ({
            label: d.domain || d.label || 'Unknown',
            bytes: d.bytes || d.total_bytes || 0,
          }))
        );
      }
      if (findingsRes.ok) {
        const data = await findingsRes.json();
        setFindings(Array.isArray(data) ? data : []);
      }
    } catch {
      // ignore
    }
  }, []);

  const fetchRestState = useCallback(async () => {
    try {
      const [healthRes, summaryRes, flowsRes] = await Promise.all([
        fetch('/api/health'),
        fetch('/api/summary'),
        fetch('/api/flows?limit=100'),
      ]);

      if (healthRes.ok) {
        const h = await healthRes.json();
        setIsConnected(Boolean(h.engine_connected));
      }

      if (summaryRes.ok) {
        const s = await summaryRes.json();
        setIsConnected(Boolean(s.engine_connected));
        pushTelemetryTick(s.current_bps || 0, s.current_pps || 0, s.active_flows || 0, s);
      }

      if (flowsRes.ok) {
        const fData = await flowsRes.json();
        const rawList = Array.isArray(fData) ? fData : fData.flows || [];
        setFlows(processFlows(rawList));
      }
    } catch {
      // Not connected
    }
  }, [pushTelemetryTick, processFlows]);

  const connectWebSocket = useCallback(() => {
    if (
      wsRef.current &&
      (wsRef.current.readyState === WebSocket.OPEN ||
        wsRef.current.readyState === WebSocket.CONNECTING)
    ) {
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'tick' || data.type === 'init') {
          if (data.summary) {
            setIsConnected(Boolean(data.summary.engine_connected));
            pushTelemetryTick(
              data.summary.current_bps || 0,
              data.summary.current_pps || 0,
              data.summary.active_flows || 0,
              data.summary
            );
          }
          if (data.active_flows) {
            setFlows(processFlows(data.active_flows));
          }
          if (data.findings) {
            setFindings(data.findings);
          }
        }
      } catch (err) {
        console.error('Failed to parse WS tick:', err);
      }
    };

    ws.onclose = () => {
      wsRef.current = null;
      setIsConnected(false);
      reconnectTimeoutRef.current = window.setTimeout(() => {
        connectWebSocket();
      }, 2000);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [pushTelemetryTick, processFlows]);

  // Fetch History ONLY when historyRange changes (and refresh quietly every 30s without unmounting!)
  useEffect(() => {
    const controller = new AbortController();
    setIsHistoryLoading(true);

    const loadHistory = (showSpinner: boolean) => {
      if (showSpinner) setIsHistoryLoading(true);
      const minutes = Math.min(rangeToMinutes(historyRange), 43200);

      Promise.all([
        fetch(`/api/history?minutes=${minutes}`, { signal: controller.signal }).then((r) =>
          r.ok ? r.json() : []
        ),
        fetch(`/api/apps?minutes=${minutes}`, { signal: controller.signal }).then((r) =>
          r.ok ? r.json() : []
        ),
        fetch(`/api/domains?minutes=${minutes}`, { signal: controller.signal }).then((r) =>
          r.ok ? r.json() : []
        ),
      ])
        .then(([histData, appsData, domsData]) => {
          const series: HistoryPoint[] = (histData || []).map((pt: any) => {
            let label = '';
            if (pt.timestamp_iso) {
              const d = new Date(pt.timestamp_iso);
              label = d.toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
              });
            } else if (pt.minute !== undefined) {
              label = `${pt.minute}m`;
            } else {
              label = '00:00';
            }
            const mbps = pt.bps ? Number((pt.bps / 1_000_000).toFixed(2)) : 0;
            return { timestampLabel: label, mbps };
          });

          // Aggregate top 5 historical applications + "Other" so the Donut legend never overflows
          const protoMap = new Map<string, number>();
          for (const pt of histData || []) {
            if (pt.app_breakdown) {
              for (const [app, bytes] of Object.entries(pt.app_breakdown)) {
                protoMap.set(app, (protoMap.get(app) || 0) + Number(bytes));
              }
            }
          }

          const sortedProtos = Array.from(protoMap.entries())
            .map(([name, value]) => ({ name, value }))
            .filter((x) => x.value > 0)
            .sort((a, b) => b.value - a.value);

          let cappedProtos = sortedProtos.slice(0, 5);
          if (sortedProtos.length > 5) {
            const otherSum = sortedProtos
              .slice(5)
              .reduce((acc, cur) => acc + cur.value, 0);
            if (otherSum > 0) {
              cappedProtos.push({ name: 'Other', value: otherSum });
            }
          }

          setHistorySeries(series);
          setHistoryProtocols(cappedProtos);
          setHistoryApps(
            (appsData || []).slice(0, 6).map((a: any) => ({
              label: a.app || 'Unknown',
              bytes: a.bytes || 0,
            }))
          );
          setHistoryDomains(
            (domsData || []).slice(0, 6).map((d: any) => ({
              label: d.domain || 'Unknown',
              bytes: d.bytes || 0,
            }))
          );
          setIsHistoryLoading(false);
        })
        .catch((err) => {
          if (err.name !== 'AbortError') {
            setIsHistoryLoading(false);
          }
        });
    };

    loadHistory(true);
    const quietRefresh = setInterval(() => loadHistory(false), 30000);

    return () => {
      clearInterval(quietRefresh);
      controller.abort();
    };
  }, [historyRange]);

  useEffect(() => {
    fetchRestState();
    fetchRules();
    fetchAnalytics();
    connectWebSocket();

    const pollInterval = setInterval(() => {
      fetchRestState();
      fetchAnalytics();
    }, 4000);

    return () => {
      clearInterval(pollInterval);
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [fetchRestState, fetchRules, fetchAnalytics, connectWebSocket]);

  const overview: OverviewProps = {
    liveBandwidthBps,
    bandwidthDeltaPct,
    packetsPerSec,
    packetsDeltaPct,
    avgPacketSizeBytes,
    packetSizeDeltaPct,
    newConnectionsPerSec,
    connectionsDeltaPct,
    bandwidthSeries,
    protocolBreakdown: liveProtocols,
    topTalkers,
    topDestinations,
    topServices,
  };

  const history: HistoryViewProps = {
    isLoading: isHistoryLoading,
    series: historySeries,
    protocolBreakdown: historyProtocols.length > 0 ? historyProtocols : liveProtocols,
    topTalkers: historyApps.length > 0 ? historyApps : topTalkers,
    topDestinations: historyDomains.length > 0 ? historyDomains : topDestinations,
    topServices,
  };

  const historyWindowLabel = useMemo(() => formatPresetDates(historyRange), [historyRange]);

  return {
    isConnected,
    summaryMeta,
    historyWindowLabel,
    overview,
    flows,
    findings,
    acknowledgeFinding,
    history,
    topApps,
    topDomains,
    rules,
    addRule,
    removeRule,
  };
}
