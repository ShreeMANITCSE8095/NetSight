/**
 * Formats bits per second dynamically so low traffic never rounds down to "0.00 Mbps"
 * Matches video 00:02 ("1.33 Mbps") and 00:48 ("2.08 Kbps", "304 bps")
 */
export function formatBitrate(bitsPerSec: number): string {
  if (!Number.isFinite(bitsPerSec) || bitsPerSec <= 0) return '0 bps';
  if (bitsPerSec < 1_000) return `${Math.round(bitsPerSec)} bps`;
  if (bitsPerSec < 1_000_000) return `${(bitsPerSec / 1_000).toFixed(2)} Kbps`;
  if (bitsPerSec < 1_000_000_000) return `${(bitsPerSec / 1_000_000).toFixed(2)} Mbps`;
  return `${(bitsPerSec / 1_000_000_000).toFixed(2)} Gbps`;
}

// Backward-compatibility alias
export const formatBitsPerSec = formatBitrate;

/**
 * Formats byte volume into "76 Bytes", "332.9 KB", "845.9 MB", "1.5 GB"
 * Matches video 00:24-00:38 & 01:18
 */
export function formatBytes(bytes: number, decimals = 1): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 Bytes';
  if (bytes < 1024) return `${Math.round(bytes)} Bytes`;
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
}

/**
 * Splits formatted bytes into [numberPart, unitPart] for stacked labels on short bars (00:36)
 */
export function splitFormattedBytes(bytes: number): { num: string; unit: string; full: string } {
  const full = formatBytes(bytes, 1);
  const [num, unit] = full.split(' ');
  return { num: num || '0', unit: unit || 'Bytes', full };
}

/**
 * Safe percentage delta calculation avoiding NaN / Infinity
 */
export function calcDeltaPercent(current: number, baseline: number): number {
  if (!Number.isFinite(current) || !Number.isFinite(baseline) || baseline <= 0) {
    return 0;
  }
  const delta = ((current - baseline) / baseline) * 100;
  return Math.max(Math.min(delta, 999.9), -99.9);
}

export function calculateEmaDelta(
  curr: number,
  prevEma: number,
  alpha: number = 0.33
): { nextEma: number; deltaPct: number } {
  if (!Number.isFinite(curr) || curr < 0) curr = 0;
  if (!Number.isFinite(prevEma) || prevEma <= 0) {
    return { nextEma: curr, deltaPct: 0 };
  }
  const nextEma = alpha * curr + (1 - alpha) * prevEma;
  const rawPct = ((curr - prevEma) / prevEma) * 100;
  const deltaPct = Number.isFinite(rawPct) ? Math.max(-100, Math.min(999, rawPct)) : 0;
  return { nextEma, deltaPct };
}

export function formatPackets(count: number | undefined | null): string {
  if (count === undefined || count === null || !Number.isFinite(count) || count <= 0) return '0';
  if (count < 1000) return count.toString();
  if (count < 1000000) return `${(count / 1000).toFixed(1)}k`;
  return `${(count / 1000000).toFixed(2)}M`;
}

export function formatTimestamp(ms: number): string {
  if (!ms || ms <= 0 || !Number.isFinite(ms)) return '\u2014';
  const d = new Date(ms);
  return d.toTimeString().split(' ')[0] + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

export function formatDuration(sec: number): string {
  if (!Number.isFinite(sec) || sec <= 0) return '0s';
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}h ${m % 60}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function isValidIpOrCidr(val: string): boolean {
  if (!val || typeof val !== 'string') return false;
  const trimmed = val.trim();
  const ipv4Regex = /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\/(3[0-2]|[1-2]?[0-9]))?$/;
  if (ipv4Regex.test(trimmed)) return true;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(\/(12[0-8]|1[0-1][0-9]|[1-9]?[0-9]))?$/;
  const ipv6Short = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(\/(12[0-8]|1[0-1][0-9]|[1-9]?[0-9]))?$/;
  if (trimmed.includes(':') && (ipv6Regex.test(trimmed) || ipv6Short.test(trimmed))) {
    return true;
  }
  return false;
}

export function formatRelativeTime(timestamp: number | string | undefined | null): string {
  if (!timestamp) return '—';
  const now = Date.now();
  let timeMs = typeof timestamp === 'string' ? new Date(timestamp).getTime() : timestamp;
  if (!Number.isFinite(timeMs) || timeMs <= 0) return '—';
  if (timeMs > 1e14) timeMs = Math.floor(timeMs / 1000);
  const diffSec = Math.max(0, Math.floor((now - timeMs) / 1000));
  if (diffSec < 2) return 'just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour}h ago`;
  return `${Math.floor(diffHour / 24)}d ago`;
}


export const APP_PALETTE = [
  '#2563EB', // Blue
  '#0D9488', // Teal
  '#D97706', // Amber
  '#7C3AED', // Violet
  '#E11D48', // Rose
  '#059669', // Emerald
  '#475569', // Slate
  '#94A3B8', // Other
];

const APP_COLOR_MAP: Record<string, string> = {
  YouTube: '#E11D48',
  Google: '#2563EB',
  TLS: '#0D9488',
  HTTPS: '#0D9488',
  DNS: '#D97706',
  QUIC: '#7C3AED',
  Unlabeled: '#94A3B8',
  UNKNOWN: '#94A3B8',
};

export function getAppColor(appOrIndex: string | number): string {
  if (typeof appOrIndex === 'string') {
    if (APP_COLOR_MAP[appOrIndex]) return APP_COLOR_MAP[appOrIndex];
    let hash = 0;
    for (let i = 0; i < appOrIndex.length; i++) {
      hash = (hash << 5) - hash + appOrIndex.charCodeAt(i);
      hash |= 0;
    }
    const idx = Math.abs(hash) % APP_PALETTE.length;
    return APP_PALETTE[idx];
  }
  return APP_PALETTE[Math.min(appOrIndex, APP_PALETTE.length - 1)];
}
