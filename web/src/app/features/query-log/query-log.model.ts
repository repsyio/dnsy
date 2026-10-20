import type { components } from '../../api/schema';

export type LogRecord = components['schemas']['LogRecord'];
export type LogPage = components['schemas']['LogPageBody'];

export type RangeKey = 'all' | '15m' | '1h' | '24h' | '7d' | 'custom';

export interface Filters {
  range: RangeKey;
  /** `datetime-local` values, used when `range` is `custom`. */
  customFrom: string;
  customTo: string;
  client: string;
  domain: string;
  qtype: string;
  /** Response code (`outcome` in the API). */
  rcode: string;
  /** Answer source (`source` in the API). */
  source: string;
  dnssec: string;
}

export const DEFAULT_FILTERS: Filters = {
  range: 'all',
  customFrom: '',
  customTo: '',
  client: '',
  domain: '',
  qtype: '',
  rcode: '',
  source: '',
  dnssec: '',
};

export const RANGES: { key: RangeKey; label: string; ms: number }[] = [
  { key: 'all', label: 'All time', ms: 0 },
  { key: '15m', label: 'Last 15 minutes', ms: 15 * 60_000 },
  { key: '1h', label: 'Last hour', ms: 3_600_000 },
  { key: '24h', label: 'Last 24 hours', ms: 86_400_000 },
  { key: '7d', label: 'Last 7 days', ms: 7 * 86_400_000 },
];

/** Outcome labels (the answer source) shown in the filter bar and the table. */
export const SOURCES: { value: string; label: string }[] = [
  { value: 'blocked', label: 'Blocked' },
  { value: 'cache', label: 'Cached' },
  { value: 'cache_stale', label: 'Stale' },
  { value: 'upstream', label: 'Forwarded' },
  { value: 'refused', label: 'Refused' },
  { value: 'authoritative', label: 'Authoritative' },
  { value: 'error', label: 'Error' },
];

export const DNSSEC_STATUSES = [
  'unchecked',
  'secure',
  'insecure',
  'bogus',
  'indeterminate',
] as const;
export type DnssecStatus = (typeof DNSSEC_STATUSES)[number];

export const QTYPES = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'NS',
  'PTR',
  'SOA',
  'SRV',
  'TXT',
  'DS',
  'DNSKEY',
  'HTTPS',
];
export const RCODES = ['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED', 'FORMERR', 'NOTIMP'];

export type SearchQuery = Record<string, string | number>;

export function isDnssecStatus(s: string): s is DnssecStatus {
  return (DNSSEC_STATUSES as readonly string[]).includes(s);
}

export function sourceLabel(source: string): string {
  return SOURCES.find((s) => s.value === source)?.label ?? source;
}

function parseLocal(value: string): number | undefined {
  if (!value) return undefined;
  const t = new Date(value).getTime();
  return Number.isNaN(t) ? undefined : t;
}

/**
 * Filters as API query parameters; empty filters are left out. The live tail passes
 * `withTime = false` since it only ever shows new rows.
 */
export function toQuery(f: Filters, now: number, withTime = true): SearchQuery {
  const q: SearchQuery = {};
  if (withTime) {
    if (f.range === 'custom') {
      const from = parseLocal(f.customFrom);
      const to = parseLocal(f.customTo);
      if (from !== undefined) q['from'] = from;
      if (to !== undefined) q['to'] = to;
    } else {
      const ms = RANGES.find((r) => r.key === f.range)?.ms ?? 0;
      if (ms > 0) q['from'] = now - ms;
    }
  }
  const text: [keyof Filters, string][] = [
    ['client', 'client'],
    ['domain', 'domain'],
    ['qtype', 'type'],
    ['rcode', 'outcome'],
    ['source', 'source'],
    ['dnssec', 'dnssec'],
  ];
  for (const [key, param] of text) {
    const v = f[key].trim();
    if (v) q[param] = v;
  }
  return q;
}

/** Prepend `incoming` (newest first) to `existing`, drop duplicate ids, keep at most `cap` rows. */
export function mergeRecords(
  existing: LogRecord[],
  incoming: LogRecord[],
  cap: number,
): LogRecord[] {
  const seen = new Set<number>();
  const out: LogRecord[] = [];
  for (const r of [...incoming, ...existing]) {
    if (seen.has(r.id)) continue;
    seen.add(r.id);
    out.push(r);
    if (out.length >= cap) break;
  }
  return out;
}

export function backoffDelay(attempt: number): number {
  return Math.min(1000 * 2 ** attempt, 30_000);
}

export function formatLatency(us: number): string {
  if (us < 1000) return `${us} µs`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(1)} ms`;
  return `${(us / 1_000_000).toFixed(2)} s`;
}

export function formatTime(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
