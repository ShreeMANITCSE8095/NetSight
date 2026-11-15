import React, { useState, useRef, useEffect } from 'react';
import {
  Gauge,
  ArrowLeftRight,
  History,
  BarChart3,
  FileSearch,
  ShieldAlert,
  Info,
  ExternalLink,
  PanelLeft,
  Sun,
  Moon,
  Calendar,
  ChevronDown,
  Infinity as InfinityIcon,
} from 'lucide-react';

export type ActiveTab =
  | 'overview'
  | 'flows'
  | 'history'
  | 'analytics'
  | 'analyze'
  | 'rules'
  | 'about';

export type ThemeMode = 'light' | 'dark' | 'system';

export type HistoryRangePreset = '1h' | '6h' | '24h' | '7d' | '30d';

interface NavbarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  isCollapsed: boolean;
  setIsCollapsed: React.Dispatch<React.SetStateAction<boolean>>;
  theme: ThemeMode;
  setTheme: (theme: ThemeMode) => void;
  isConnected: boolean;
  historyRange: HistoryRangePreset;
  setHistoryRange: (range: HistoryRangePreset) => void;
  historyWindowLabel: { start: string; end: string };
}

const HISTORY_PRESETS: { value: HistoryRangePreset; label: string }[] = [
  { value: '1h', label: 'Last 1 Hour' },
  { value: '6h', label: 'Last 6 Hours' },
  { value: '24h', label: 'Last 24 Hours' },
  { value: '7d', label: 'Last 7 Days' },
  { value: '30d', label: 'Last 30 Days' },
];

export const Sidebar: React.FC<
  Pick<NavbarProps, 'activeTab' | 'setActiveTab' | 'isCollapsed'>
> = ({ activeTab, setActiveTab, isCollapsed }) => {
  const navItems: { id: ActiveTab; label: string; icon: React.ElementType }[] = [
    { id: 'overview', label: 'Overview', icon: Gauge },
    { id: 'flows', label: 'Connections', icon: ArrowLeftRight },
    { id: 'history', label: 'History', icon: History },
    { id: 'analytics', label: 'DPI Analytics', icon: BarChart3 },
    { id: 'analyze', label: 'Analyze PCAP', icon: FileSearch },
    { id: 'rules', label: 'Firewall Rules', icon: ShieldAlert },
  ];

  return (
    <aside
      className={`${
        isCollapsed ? 'w-14' : 'w-60'
      } flex-shrink-0 bg-sidebar border-r border-subtle flex flex-col justify-between transition-all duration-200 select-none`}
    >
      {/* Top Brand Header + Primary Nav */}
      <div className="p-2.5 flex flex-col gap-4">
        <div
          className={`flex items-center ${
            isCollapsed ? 'justify-center' : 'px-2.5 gap-2.5'
          } pt-1`}
        >
          <div className="w-7 h-7 rounded-lg bg-[#4F46E5]/10 flex items-center justify-center text-[#4F46E5]">
            <InfinityIcon className="w-5 h-5 stroke-[2.2]" />
          </div>
          {!isCollapsed && (
            <span className="text-[15px] font-semibold tracking-tight text-primary">
              NetSight
            </span>
          )}
        </div>

        <nav className="flex flex-col gap-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                title={isCollapsed ? item.label : undefined}
                className={`flex items-center ${
                  isCollapsed ? 'justify-center px-0 py-2' : 'px-3 py-2 gap-2.5'
                } rounded-lg text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-black/[0.06] dark:bg-white/[0.08] text-primary font-semibold'
                    : 'text-secondary hover:text-primary hover:bg-black/[0.03] dark:hover:bg-white/[0.04]'
                }`}
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                {!isCollapsed && <span>{item.label}</span>}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Footer Links (Matches 00:00 & 01:28) */}
      <div className="p-2.5 flex flex-col gap-1 border-t border-subtle/60">
        <button
          onClick={() => setActiveTab('about')}
          title={isCollapsed ? 'About NetSight' : undefined}
          className={`flex items-center ${
            isCollapsed ? 'justify-center px-0 py-2' : 'px-3 py-2 gap-2.5'
          } rounded-lg text-xs font-medium transition-colors ${
            activeTab === 'about'
              ? 'bg-black/[0.06] dark:bg-white/[0.08] text-primary font-semibold'
              : 'text-secondary hover:text-primary hover:bg-black/[0.03] dark:hover:bg-white/[0.04]'
          }`}
        >
          <Info className="w-4 h-4 flex-shrink-0" />
          {!isCollapsed && <span>About NetSight</span>}
        </button>

        <a
          href="https://shree-pandit-portfolio.vercel.app"
          target="_blank"
          rel="noreferrer"
          title={isCollapsed ? 'Shree Pandit' : undefined}
          className={`flex items-center ${
            isCollapsed ? 'justify-center px-0 py-2' : 'px-3 py-2 gap-2.5'
          } rounded-lg text-xs font-medium text-secondary hover:text-primary hover:bg-black/[0.03] dark:hover:bg-white/[0.04] transition-colors`}
        >
          <ExternalLink className="w-4 h-4 flex-shrink-0" />
          {!isCollapsed && <span>Shree Pandit</span>}
        </a>
      </div>
    </aside>
  );
};

export const TopHeaderBar: React.FC<NavbarProps> = ({
  activeTab,
  isCollapsed,
  setIsCollapsed,
  theme,
  setTheme,
  isConnected,
  historyRange,
  setHistoryRange,
  historyWindowLabel,
}) => {
  const [themeMenuOpen, setThemeMenuOpen] = useState(false);
  const [rangeMenuOpen, setRangeMenuOpen] = useState(false);
  const themeRef = useRef<HTMLDivElement>(null);
  const rangeRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (themeRef.current && !themeRef.current.contains(e.target as Node)) {
        setThemeMenuOpen(false);
      }
      if (rangeRef.current && !rangeRef.current.contains(e.target as Node)) {
        setRangeMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const titleMap: Record<ActiveTab, string> = {
    overview: 'Overview',
    flows: 'Connections',
    history: 'History',
    analytics: 'DPI Analytics',
    analyze: 'Analyze PCAP',
    rules: 'Firewall Rules',
    about: 'About NetSight',
  };

  const currentRangeLabel =
    HISTORY_PRESETS.find((p) => p.value === historyRange)?.label || 'Last 24 Hours';

  return (
    <header className="h-12 flex-shrink-0 bg-canvas border-b border-subtle px-4 flex items-center justify-between">
      {/* Left: Sidebar Toggle + Divider + View Title */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => setIsCollapsed(!isCollapsed)}
          className="p-1.5 rounded-md text-secondary hover:text-primary hover:bg-black/5 dark:hover:bg-white/5 transition-colors"
          title="Toggle Sidebar"
        >
          <PanelLeft className="w-4 h-4" />
        </button>
        <div className="h-4 w-[1px] bg-subtle" />
        <h1 className="text-xs font-semibold text-primary">{titleMap[activeTab]}</h1>
      </div>

      {/* Right: History Controls (01:06-01:12) + Engine Status + Theme Switcher (00:46) */}
      <div className="flex items-center gap-2.5">
        {activeTab === 'history' && (
          <div className="hidden md:flex items-center gap-2">
            {/* Time Preset Dropdown */}
            <div className="relative" ref={rangeRef}>
              <button
                onClick={() => setRangeMenuOpen((o) => !o)}
                className="h-8 px-3 rounded-lg bg-surface border border-subtle text-xs font-medium text-primary flex items-center gap-3 hover:border-neutral-400 dark:hover:border-neutral-600 transition-colors"
              >
                <span>{currentRangeLabel}</span>
                <ChevronDown className="w-3.5 h-3.5 text-secondary" />
              </button>

              {rangeMenuOpen && (
                <div className="absolute right-0 mt-1.5 w-40 rounded-lg bg-surface border border-subtle shadow-lg py-1 z-30">
                  {HISTORY_PRESETS.map((preset) => (
                    <button
                      key={preset.value}
                      onClick={() => {
                        setHistoryRange(preset.value);
                        setRangeMenuOpen(false);
                      }}
                      className={`w-full px-3 py-1.5 text-left text-xs flex items-center justify-between hover:bg-black/5 dark:hover:bg-white/5 ${
                        historyRange === preset.value
                          ? 'font-semibold text-primary'
                          : 'text-secondary'
                      }`}
                    >
                      <span>{preset.label}</span>
                      {historyRange === preset.value && <span>✓</span>}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Start Timestamp Pill */}
            <div className="h-8 px-3 rounded-lg bg-surface border border-subtle text-[11px] font-medium text-primary flex items-center gap-2 tabular-nums">
              <Calendar className="w-3.5 h-3.5 text-secondary" />
              <span>{historyWindowLabel.start}</span>
            </div>

            {/* End Timestamp Pill */}
            <div className="h-8 px-3 rounded-lg bg-surface border border-subtle text-[11px] font-medium text-primary flex items-center gap-2 tabular-nums">
              <Calendar className="w-3.5 h-3.5 text-secondary" />
              <span>{historyWindowLabel.end}</span>
            </div>
          </div>
        )}

        {/* Subtle Live Engine Indicator */}
        <div
          className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-surface border border-subtle text-[11px] text-secondary"
          title={isConnected ? 'C++ DPI Engine Connected' : 'Waiting for Telemetry Stream'}
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              isConnected ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'
            }`}
          />
          <span>{isConnected ? 'Live' : 'Standby'}</span>
        </div>

        {/* Light / Dark / System Dropdown (Matches 00:46) */}
        <div className="relative" ref={themeRef}>
          <button
            onClick={() => setThemeMenuOpen((o) => !o)}
            className="w-8 h-8 rounded-lg bg-surface border border-subtle flex items-center justify-center text-secondary hover:text-primary transition-colors"
            title="Switch Theme"
          >
            {theme === 'light' ? (
              <Sun className="w-4 h-4" />
            ) : (
              <Moon className="w-4 h-4" />
            )}
          </button>

          {themeMenuOpen && (
            <div className="absolute right-0 mt-1.5 w-28 rounded-lg bg-surface border border-subtle shadow-lg py-1 z-30">
              {(['light', 'dark', 'system'] as ThemeMode[]).map((mode) => (
                <button
                  key={mode}
                  onClick={() => {
                    setTheme(mode);
                    setThemeMenuOpen(false);
                  }}
                  className={`w-full px-3 py-1.5 text-left text-xs capitalize hover:bg-black/5 dark:hover:bg-white/5 ${
                    theme === mode ? 'font-semibold text-primary' : 'text-secondary'
                  }`}
                >
                  {mode}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
