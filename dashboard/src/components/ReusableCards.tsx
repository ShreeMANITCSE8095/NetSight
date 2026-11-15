import React, { useState } from 'react';
import { ArrowUpRight, ArrowDownRight, Minus } from 'lucide-react';
import { formatBytes, splitFormattedBytes } from '../utils';

export interface KpiCardProps {
  title: string;
  value: string;
  subtitle: string;
  deltaPercent: number;
}

export const KpiCard: React.FC<KpiCardProps> = ({
  title,
  value,
  subtitle,
  deltaPercent,
}) => {
  const isPositive = deltaPercent > 0.1;
  const isNegative = deltaPercent < -0.1;

  return (
    <div className="rounded-xl bg-surface border border-subtle p-5 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-secondary">{title}</span>
        {isPositive ? (
          <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400 tabular-nums">
            <ArrowUpRight className="w-3 h-3" /> +{deltaPercent.toFixed(1)}%
          </span>
        ) : isNegative ? (
          <span className="inline-flex items-center gap-1 rounded-full bg-rose-500/10 px-2 py-0.5 text-[11px] font-semibold text-rose-600 dark:text-rose-400 tabular-nums">
            <ArrowDownRight className="w-3 h-3" /> {deltaPercent.toFixed(1)}%
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 rounded-full bg-neutral-500/10 px-2 py-0.5 text-[11px] font-semibold text-secondary tabular-nums">
            <Minus className="w-3 h-3" /> 0%
          </span>
        )}
      </div>

      <div className="my-2.5 text-[30px] leading-tight font-bold tracking-tight text-primary tabular-nums">
        {value}
      </div>

      <div className="text-xs text-secondary">{subtitle}</div>
    </div>
  );
};

export interface TopBarItem {
  label: string;
  bytes: number;
}

export const TopTrafficCard: React.FC<{
  title: string;
  subtitle: string;
  items: TopBarItem[];
  emptyMessage?: string;
}> = ({ title, subtitle, items, emptyMessage = 'No traffic recorded yet' }) => {
  const [hoveredLabel, setHoveredLabel] = useState<string | null>(null);
  const topItems = items.slice(0, 6);
  const maxBytes = Math.max(...topItems.map((i) => i.bytes), 1);

  return (
    <div className="rounded-xl bg-surface border border-subtle p-5 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col min-h-[270px]">
      <h3 className="text-sm font-semibold text-primary">{title}</h3>
      <p className="text-xs text-secondary mb-4">{subtitle}</p>

      {topItems.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-xs text-secondary">
          {emptyMessage}
        </div>
      ) : (
        <div className="flex-1 flex flex-col justify-center">
          {topItems.map((item) => {
            const pct = Math.max((item.bytes / maxBytes) * 100, 1.5);
            const { num, unit, full } = splitFormattedBytes(item.bytes);
            const isShortBar = pct < 22;

            return (
              <div
                key={item.label}
                className="relative grid grid-cols-12 items-center group"
                onMouseEnter={() => setHoveredLabel(item.label)}
                onMouseLeave={() => setHoveredLabel(null)}
              >
                {/* Left Monospace IP / Port column with right axis line (matches 00:24 & 01:18) */}
                <div className="col-span-4 pr-3 py-1.5 text-right font-mono text-[11px] text-secondary truncate border-r border-subtle">
                  {item.label}
                </div>

                {/* Right Horizontal Indigo Bar + outside byte counter */}
                <div className="col-span-8 pl-0.5 py-1 flex items-center gap-2 pr-12">
                  <div
                    className="h-7 rounded-r-[4px] bg-[#4F46E5] transition-all duration-300 flex-shrink-0"
                    style={{ width: `${pct}%` }}
                  />
                  {isShortBar ? (
                    <div className="flex flex-col leading-[1.05] text-[10px] font-bold text-primary tabular-nums">
                      <span>{num}</span>
                      <span>{unit}</span>
                    </div>
                  ) : (
                    <span className="text-[11px] font-bold text-primary tabular-nums whitespace-nowrap">
                      {full}
                    </span>
                  )}
                </div>

                {/* Floating tooltip on bar hover (matches 00:24 & 01:18) */}
                {hoveredLabel === item.label && (
                  <div className="pointer-events-none absolute left-1/2 -top-8 -translate-x-1/2 z-20 rounded-md bg-surface border border-subtle px-2.5 py-1 text-[11px] font-medium text-primary shadow-md flex items-center gap-1.5 whitespace-nowrap">
                    <span className="w-2 h-2 rounded-[2px] bg-[#4F46E5]" />
                    <span className="font-semibold tabular-nums">{formatBytes(item.bytes, 2)}</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
