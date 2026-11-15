import React, { useMemo } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { KpiCard, TopTrafficCard, TopBarItem } from './ReusableCards';
import { formatBitrate } from '../utils';

export interface BandwidthPoint {
  label: string; // "50s", "40s", ..., "0s"
  mbps: number;
  bps: number;
}

export interface OverviewProps {
  liveBandwidthBps: number;
  bandwidthDeltaPct: number;
  packetsPerSec: number;
  packetsDeltaPct: number;
  avgPacketSizeBytes: number;
  packetSizeDeltaPct: number;
  newConnectionsPerSec: number;
  connectionsDeltaPct: number;
  bandwidthSeries: BandwidthPoint[];
  protocolBreakdown: { name: string; value: number }[];
  topTalkers: TopBarItem[];
  topDestinations: TopBarItem[];
  topServices: TopBarItem[];
}

const PROTOCOL_COLORS = ['#4F46E5', '#818CF8', '#A5B4FC', '#C7D2FE'];

export const OverviewView: React.FC<OverviewProps> = ({
  liveBandwidthBps,
  bandwidthDeltaPct,
  packetsPerSec,
  packetsDeltaPct,
  avgPacketSizeBytes,
  packetSizeDeltaPct,
  newConnectionsPerSec,
  connectionsDeltaPct,
  bandwidthSeries,
  protocolBreakdown,
  topTalkers,
  topDestinations,
  topServices,
}) => {
  // Determine if chart should display in Kbps or Mbps so low traffic is still visible
  const maxBps = useMemo(
    () => Math.max(...bandwidthSeries.map((d) => d.bps), 0),
    [bandwidthSeries]
  );
  const useKbpsAxis = maxBps > 0 && maxBps < 100_000; // under 100 Kbps

  const chartData = useMemo(
    () =>
      bandwidthSeries.map((pt) => ({
        ...pt,
        displayValue: useKbpsAxis
          ? Number((pt.bps / 1_000).toFixed(2))
          : Number((pt.bps / 1_000_000).toFixed(2)),
      })),
    [bandwidthSeries, useKbpsAxis]
  );

  const activeProtocols = useMemo(() => {
    const filtered = protocolBreakdown.filter((p) => p.value > 0);
    return filtered.length > 0 ? filtered : [{ name: 'TCP', value: 1 }];
  }, [protocolBreakdown]);

  return (
    <div className="flex flex-col gap-4">
      {/* Row 1: 4 Auralis KPI Cards (00:02 - 00:12) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <KpiCard
          title="Live Bandwidth"
          value={formatBitrate(liveBandwidthBps)}
          subtitle="Network Speed"
          deltaPercent={bandwidthDeltaPct}
        />
        <KpiCard
          title="Packets/Sec"
          value={Math.round(packetsPerSec).toLocaleString()}
          subtitle="Packets per Second"
          deltaPercent={packetsDeltaPct}
        />
        <KpiCard
          title="Avg. Packet Size"
          value={Math.round(avgPacketSizeBytes).toString()}
          subtitle="Bytes"
          deltaPercent={packetSizeDeltaPct}
        />
        <KpiCard
          title="Active Connections"
          value={Math.round(newConnectionsPerSec).toLocaleString()}
          subtitle="Concurrent Flows"
          deltaPercent={connectionsDeltaPct}
        />
      </div>

      {/* Row 2: Bandwidth History AreaChart (col-span-8) + Protocol Donut (col-span-4) (00:12 - 00:22) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Bandwidth History */}
        <div className="lg:col-span-8 rounded-xl bg-surface border border-subtle p-5 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col">
          <h3 className="text-sm font-semibold text-primary">Bandwidth History</h3>
          <p className="text-xs text-secondary mb-4">Live network throughput</p>

          <div className="h-[240px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={chartData}
                margin={{ top: 8, right: 12, left: 0, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="auralisBandwidthGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#4F46E5" stopOpacity={0.38} />
                    <stop offset="95%" stopColor="#4F46E5" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid
                  vertical={false}
                  stroke="var(--grid-line)"
                  strokeDasharray="3 3"
                />
                <XAxis
                  dataKey="label"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                  interval={9}
                />
                <YAxis
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                  tickFormatter={(v) => Number(v).toFixed(2)}
                  label={{
                    value: useKbpsAxis ? 'Kbps' : 'Mbps',
                    angle: -90,
                    position: 'insideLeft',
                    style: {
                      fill: 'var(--text-secondary)',
                      fontSize: 11,
                      textAnchor: 'middle',
                    },
                  }}
                />
                <Tooltip
                  isAnimationActive={false}
                  content={({ active, payload }) => {
                    if (!active || !payload || !payload.length) return null;
                    const val = payload[0].value as number;
                    return (
                      <div className="rounded-lg bg-surface border border-subtle px-3 py-2 shadow-md text-xs flex items-center gap-2">
                        <span className="w-1 h-6 rounded-full bg-[#4F46E5]" />
                        <div>
                          <div className="text-secondary text-[11px]">Bandwidth</div>
                          <div className="font-bold text-primary tabular-nums">
                            {val} {useKbpsAxis ? 'Kbps' : 'Mbps'}
                          </div>
                        </div>
                      </div>
                    );
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="displayValue"
                  stroke="#4F46E5"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#auralisBandwidthGrad)"
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right: Protocol Distribution Donut */}
        <div className="lg:col-span-4 rounded-xl bg-surface border border-subtle p-5 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-primary">Protocol Distribution</h3>
            <p className="text-xs text-secondary">Live traffic breakdown by protocol</p>
          </div>

          <div className="h-[195px] w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={activeProtocols}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={58}
                  outerRadius={82}
                  stroke="none"
                  paddingAngle={0}
                  isAnimationActive={false}
                >
                  {activeProtocols.map((entry, idx) => (
                    <Cell
                      key={entry.name}
                      fill={PROTOCOL_COLORS[idx % PROTOCOL_COLORS.length]}
                    />
                  ))}
                </Pie>
                <Tooltip
                  isAnimationActive={false}
                  content={({ active, payload }) => {
                    if (!active || !payload || !payload.length) return null;
                    const item = payload[0];
                    return (
                      <div className="rounded-md bg-neutral-900 text-white px-2.5 py-1 text-[11px] font-medium shadow-md flex items-center gap-1.5 tabular-nums">
                        <span
                          className="w-2 h-2 rounded-[2px]"
                          style={{ backgroundColor: item.payload?.fill || '#4F46E5' }}
                        />
                        <span>{item.name}</span>
                        <span className="font-bold">
                          {Number(item.value).toLocaleString()}
                        </span>
                      </div>
                    );
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Bottom Inline Legend (TCP / UDP) */}
          <div className="flex items-center justify-center gap-4 pt-1">
            {activeProtocols.map((entry, idx) => (
              <div key={entry.name} className="flex items-center gap-1.5 text-xs text-primary">
                <span
                  className="w-2.5 h-2.5 rounded-[2px]"
                  style={{
                    backgroundColor: PROTOCOL_COLORS[idx % PROTOCOL_COLORS.length],
                  }}
                />
                <span>{entry.name}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 3: 3 Equal Horizontal Bar Cards (00:24 - 00:40) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <TopTrafficCard
          title="Top Talkers"
          subtitle="Top source IPs by traffic volume"
          items={topTalkers}
        />
        <TopTrafficCard
          title="Top Destination"
          subtitle="Top destination IPs by traffic volume"
          items={topDestinations}
        />
        <TopTrafficCard
          title="Top Services"
          subtitle="Top destination ports by traffic volume"
          items={topServices}
        />
      </div>
    </div>
  );
};
