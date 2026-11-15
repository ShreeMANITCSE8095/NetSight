import React, { useState, useEffect } from 'react';
import {
  Sidebar,
  TopHeaderBar,
  ActiveTab,
  ThemeMode,
  HistoryRangePreset,
} from './components/Navbar';
import { OverviewView } from './components/OverviewView';
import { FlowsView } from './components/FlowsView';
import { HistoryView } from './components/HistoryView';
import { AnalyticsView } from './components/AnalyticsView';
import { AnalyzeView } from './components/AnalyzeView';
import { RulesView } from './components/RulesView';
import { useNetSightTelemetry } from './hooks/useNetSightTelemetry';
import {
  Gauge,
  BarChart2,
  TrendingUp,
  Share2,
  Smartphone,
  Sun,
} from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [theme, setTheme] = useState<ThemeMode>('dark');
  const [historyRange, setHistoryRange] = useState<HistoryRangePreset>('24h');

  // Apply Light / Dark / System class to <html>
  useEffect(() => {
    const root = document.documentElement;
    const applyTheme = (mode: ThemeMode) => {
      if (mode === 'system') {
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        root.classList.toggle('dark', prefersDark);
      } else {
        root.classList.toggle('dark', mode === 'dark');
      }
    };
    applyTheme(theme);
  }, [theme]);

  const telemetry = useNetSightTelemetry(historyRange);

  return (
    <div className="min-h-screen flex bg-canvas text-primary">
      {/* Left Collapsible Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isCollapsed={isCollapsed}
      />

      {/* Right Main Column */}
      <div className="flex-1 flex flex-col min-w-0">
        <TopHeaderBar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          isCollapsed={isCollapsed}
          setIsCollapsed={setIsCollapsed}
          theme={theme}
          setTheme={setTheme}
          isConnected={telemetry.isConnected}
          historyRange={historyRange}
          setHistoryRange={setHistoryRange}
          historyWindowLabel={telemetry.historyWindowLabel}
        />

        <main className="flex-1 p-5 overflow-y-auto">
          {activeTab === 'overview' && <OverviewView {...telemetry.overview} />}
          {activeTab === 'flows' && <FlowsView flows={telemetry.flows} />}
          {activeTab === 'history' && <HistoryView {...telemetry.history} />}
          {activeTab === 'analytics' && (
            <AnalyticsView
              topApps={telemetry.topApps}
              topDomains={telemetry.topDomains}
              flows={telemetry.flows}
              findings={telemetry.findings}
              summaryMeta={telemetry.summaryMeta}
              onAcknowledgeFinding={telemetry.acknowledgeFinding}
            />
          )}
          {activeTab === 'analyze' && <AnalyzeView />}
          {activeTab === 'rules' && (
            <RulesView
              rules={telemetry.rules}
              onAddRule={telemetry.addRule}
              onRemoveRule={telemetry.removeRule}
            />
          )}
          {activeTab === 'about' && <AboutView />}
        </main>
      </div>
    </div>
  );
}

/* Matches the exact "About" screen at 01:30 - 01:42 in the reference video */
const AboutView: React.FC = () => {
  const features = [
    {
      icon: Gauge,
      title: 'Real-Time Metrics',
      desc: 'Monitor live bandwidth, packets per second, and other key performance indicators at a glance.',
    },
    {
      icon: BarChart2,
      title: 'Interactive Charts',
      desc: 'Visualize network data with dynamic, easy-to-understand charts for bandwidth, protocol distribution, and more.',
    },
    {
      icon: TrendingUp,
      title: 'Top Traffic Analysis',
      desc: 'Instantly identify the top talkers, destinations, and services consuming bandwidth on your network.',
    },
    {
      icon: Share2,
      title: 'Detailed Connection Info',
      desc: 'Inspect a comprehensive table of active network connections, including IPs, ports, and data volume.',
    },
    {
      icon: Smartphone,
      title: 'Responsive Design',
      desc: 'NetSight is designed to work seamlessly across devices, from large desktop monitors to tablets.',
    },
    {
      icon: Sun,
      title: 'Light & Dark Mode',
      desc: 'Seamlessly switch between light and dark themes for your viewing comfort.',
    },
  ];

  return (
    <div className="max-w-5xl mx-auto py-4 flex flex-col gap-8">
      <div className="text-center">
        <h2 className="text-3xl font-bold tracking-tight text-primary">
          Welcome to NetSight
        </h2>
        <p className="text-sm text-secondary mt-1.5">
          Your window into the world of network traffic.
        </p>
      </div>

      <div className="rounded-xl bg-surface border border-subtle p-6 text-xs leading-relaxed text-secondary space-y-3">
        <h3 className="text-sm font-semibold text-primary">The NetSight Story</h3>
        <p>
          NetSight pairs a multi-threaded C++17 Deep Packet Inspection (DPI) engine with an asynchronous FastAPI telemetry collector and a minimalist real-time interface. Instead of digging through raw command-line packet dumps, NetSight transforms high-velocity packet streams into clear, actionable visual telemetry.
        </p>
        <p>
          From five-tuple flow tracking and TLS ClientHello SNI extraction to historical SQLite time-series analysis and dynamic firewall rule enforcement, NetSight gives you the power to see, understand, and control your network traffic.
        </p>
      </div>

      <div>
        <h3 className="text-lg font-bold text-center text-primary mb-4">
          Key Features
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {features.map((f) => {
            const Icon = f.icon;
            return (
              <div
                key={f.title}
                className="rounded-xl bg-surface border border-subtle p-5 flex flex-col gap-2"
              >
                <div className="flex items-center gap-2 text-xs font-semibold text-primary">
                  <Icon className="w-4 h-4 text-[#4F46E5]" />
                  <span>{f.title}</span>
                </div>
                <p className="text-xs text-secondary leading-relaxed">{f.desc}</p>
              </div>
            );
          })}
        </div>
      </div>

      <div className="text-center text-xs text-secondary pt-2">
        Made with ❤️ by{' '}
        <a
          href="https://github.com/ShreeMANITCSE8095"
          target="_blank"
          rel="noreferrer"
          className="underline hover:text-primary"
        >
          Shree Pandit
        </a>
      </div>
    </div>
  );
};

export default App;
