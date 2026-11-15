import React, { useState, useRef } from 'react';
import { UploadCloud, AlertCircle } from 'lucide-react';
import { TopTrafficCard, TopBarItem, KpiCard } from './ReusableCards';
import { formatBytes } from '../utils';

export const AnalyzeView: React.FC = () => {
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{
    filename: string;
    total_packets: number;
    total_bytes: number;
    unique_flows: number;
    top_talkers: TopBarItem[];
    top_apps: TopBarItem[];
    top_domains: TopBarItem[];
  } | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Reset input value immediately so selecting the same PCAP file again triggers onChange
    e.target.value = '';

    setIsUploading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const res = await fetch('/api/analyze', {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const errText = await res.text();
        throw new Error(errText || `Upload failed (${res.status})`);
      }

      const data = await res.json();
      setResult({
        filename: file.name,
        total_packets: data.total_packets ?? 0,
        total_bytes: data.total_bytes ?? 0,
        unique_flows: data.unique_flows ?? 0,
        top_talkers: (data.top_talkers || []).map((t: any) => ({
          label: t.ip || t.label,
          bytes: t.bytes || t.total_bytes || 0,
        })),
        top_apps: (data.top_apps || []).map((a: any) => ({
          label: a.app || a.label,
          bytes: a.bytes || a.total_bytes || 0,
        })),
        top_domains: (data.top_domains || []).map((d: any) => ({
          label: d.domain || d.label,
          bytes: d.bytes || d.total_bytes || 0,
        })),
      });
    } catch (err: any) {
      setError(err.message || 'Failed to analyze PCAP file');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-xl bg-surface border border-subtle p-6 flex flex-col items-center justify-center text-center">
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          onChange={handleFileChange}
          className="hidden"
        />
        <div className="w-10 h-10 rounded-full bg-[#4F46E5]/10 text-[#4F46E5] flex items-center justify-center mb-3">
          <UploadCloud className="w-5 h-5" />
        </div>
        <h3 className="text-sm font-semibold text-primary">
          Offline PCAP Deep Packet Inspection
        </h3>
        <p className="text-xs text-secondary mt-1 max-w-md">
          Upload a standard <code className="font-mono">.pcap</code> capture file to run the C++17 DPI engine and extract L7 protocols, TLS SNI hostnames, and top talkers.
        </p>
        <button
          onClick={() => fileInputRef.current?.click()}
          disabled={isUploading}
          className="mt-4 px-4 py-2 rounded-lg bg-[#4F46E5] hover:bg-[#4338CA] text-white text-xs font-medium transition-colors disabled:opacity-50"
        >
          {isUploading ? 'Analyzing Capture...' : 'Select .pcap File'}
        </button>

        {error && (
          <div className="mt-3 flex items-center gap-1.5 text-xs text-rose-500">
            <AlertCircle className="w-4 h-4" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {result && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <KpiCard
              title={`File: ${result.filename}`}
              value={formatBytes(result.total_bytes, 2)}
              subtitle="Total Capture Volume"
              deltaPercent={0}
            />
            <KpiCard
              title="Total Packets"
              value={result.total_packets.toLocaleString()}
              subtitle="Inspected Frames"
              deltaPercent={0}
            />
            <KpiCard
              title="Unique Flows"
              value={result.unique_flows.toLocaleString()}
              subtitle="5-Tuple Connections"
              deltaPercent={0}
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <TopTrafficCard
              title="PCAP Top Talkers"
              subtitle="Source IPs by volume"
              items={result.top_talkers}
            />
            <TopTrafficCard
              title="PCAP Applications"
              subtitle="L7 DPI breakdown"
              items={result.top_apps}
            />
            <TopTrafficCard
              title="PCAP TLS SNI / Domains"
              subtitle="Extracted hostnames"
              items={result.top_domains}
            />
          </div>
        </>
      )}
    </div>
  );
};
