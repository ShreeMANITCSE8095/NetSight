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
import { Infinity as InfinityIcon } from 'lucide-react';
import { TopTrafficCard, TopBarItem } from './ReusableCards';
import { formatBytes } from '../utils';

export interface HistoryPoint {
  timestampLabel: string;
  mbps: number;
}

export interface HistoryViewProps {
  isLoading: boolean;
  series: HistoryPoint[];
  protocolBreakdown: { name: string; value: number }[];
  topTalkers: TopBarItem[];
  topDestinations: TopBarItem[];
  topServices: TopBarItem[];
}

const PROTOCOL_COLORS = [
  '#4F46E5',
  '#0D9488',
  '#D97706',
  '#E11D48',
  '#7C3AED',
  '#64748B',
];

export const HistoryView: React.FC<HistoryViewProps> = ({
  isLoading,
  series,
  protocolBreakdown,
  topTalkers,
  topDestinations,
  topServices,
}) => {
  const activeProtocols = useMemo(() => {
    const filtered = protocolBreakdown.filter((p) => p.value > 0);
    if (filtered.length === 0) return [{ name: 'TCP', value: 1 }];
    const sorted = [...filtered].sort((a, b) => b.value - a.value);
    if (sorted.length <= 5) return sorted;
    const top5 = sorted.slice(0, 5);
    const otherVal = sorted.slice(5).reduce((acc, cur) => acc + cur.value, 0);
    return [...top5, { name: 'Other', value: otherVal }];
  }, [protocolBreakdown]);

  if (isLoading) {
    return (
      <div className="min-h-[70vh] flex flex-col items-center justify-center gap-3">
        <InfinityIcon className="w-12 h-12 text-primary animate-pulse stroke-[2.2]" />
        <span className="text-sm font-medium text-secondary">
          Loading history data...
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-8 rounded-xl bg-surface border border-subtle p-5 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col">
          <h3 className="text-sm font-semibold text-primary">Bandwidth History</h3>
          <p className="text-xs text-secondary mb-4">Historical network throughput (1-minute SQLite rollups)</p>

          <div className="h-[240px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={series}
                margin={{ top: 8, right: 12, left: 0, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="historyBandwidthGrad" x1="0" y1="0" x2="0" y2="1">
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
                  dataKey="timestampLabel"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                  minTickGap={36}
                />
                <YAxis
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                  tickFormatter={(v) => Number(v).toFixed(2)}
                  label={{
                    value: 'Mbps',
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
                  content={({ active, payload, label }) => {
                    if (!active || !payload || !payload.length) return null;
                    return (
                      <div className="rounded-lg bg-surface border border-subtle px-3 py-2 shadow-md text-xs">
                        <div className="text-secondary text-[11px] mb-0.5">{label}</div>
                        <div className="font-bold text-primary tabular-nums">
                          {Number(payload[0].value).toFixed(2)} Mbps
                        </div>
                      </div>
                    );
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="mbps"
                  stroke="#4F46E5"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#historyBandwidthGrad)"
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol / Application Distribution Donut (Contained & Wrapped) */}
        <div className="lg:col-span-4 rounded-xl bg-surface border border-subtle p-5 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between overflow-hidden">
          <div>
            <h3 className="text-sm font-semibold text-primary">Protocol & App Share</h3>
            <p className="text-xs text-secondary">
              Historical volume breakdown (Top 5 + Other)
            </p>
          </div>

          <div className="h-[185px] w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={activeProtocols}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={52}
                  outerRadius={76}
                  stroke="none"
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
                        <span>{item.name}:</span>
                        <span className="font-bold">
                          {formatBytes(Number(item.value))}
                        </span>
                      </div>
                    );
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1.5 pt-2">
            {activeProtocols.map((entry, idx) => (
              <div
                key={entry.name}
                className="flex items-center gap-1.5 text-[11px] text-primary"
              >
                <span
                  className="w-2.5 h-2.5 rounded-[2px] flex-shrink-0"
                  style={{
                    backgroundColor: PROTOCOL_COLORS[idx % PROTOCOL_COLORS.length],
                  }}
                />
                <span className="truncate max-w-[90px]">{entry.name}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom 3 Horizontal Bar Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <TopTrafficCard
          title="Historical Top Applications"
          subtitle="Aggregated L7 application volume"
          items={topTalkers}
        />
        <TopTrafficCard
          title="Historical Top Domains"
          subtitle="Aggregated TLS SNI & DNS domains"
          items={topDestinations}
        />
        <TopTrafficCard
          title="Top Active Services"
          subtitle="Top destination ports by traffic volume"
          items={topServices}
        />
      </div>
    </div>
  );
};
