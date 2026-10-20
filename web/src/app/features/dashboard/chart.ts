import type { components } from '../../api/schema';

export type SeriesPoint = components['schemas']['SeriesPoint'];

export type RangeKey = '1h' | '24h' | '7d';

export interface RangeSpec {
  key: RangeKey;
  label: string;
  spanMs: number;
  /** Bucket width in seconds (a multiple of 60, as the API requires). */
  bucketSecs: number;
}

export const RANGES: readonly RangeSpec[] = [
  { key: '1h', label: '1 hour', spanMs: 3_600_000, bucketSecs: 60 },
  { key: '24h', label: '24 hours', spanMs: 86_400_000, bucketSecs: 900 },
  { key: '7d', label: '7 days', spanMs: 604_800_000, bucketSecs: 7200 },
];

export const CHART = { width: 720, height: 240, left: 48, right: 12, top: 12, bottom: 28 } as const;

export interface Tick {
  label: string;
  pos: number;
}

export interface ChartModel {
  totalPath: string;
  totalArea: string;
  cachePath: string;
  yTicks: Tick[];
  xTicks: Tick[];
  max: number;
  /** One row per bucket, for the table view and the text alternative. */
  rows: { start: number; total: number; cacheHits: number; blocked: number }[];
}

/** Round up to 1, 2, 5 times a power of ten so axis labels stay readable. */
export function niceCeil(value: number): number {
  if (value <= 0) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(value)));
  const f = value / exp;
  const nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  return nice * exp;
}

/** Fill the buckets the API leaves out with zeros so the line drops to zero in quiet periods. */
export function fillBuckets(
  points: readonly SeriesPoint[],
  from: number,
  to: number,
  bucketMs: number,
): SeriesPoint[] {
  const byStart = new Map(points.map((p) => [p.start_ms, p]));
  const out: SeriesPoint[] = [];
  for (let t = Math.floor(from / bucketMs) * bucketMs; t < to; t += bucketMs) {
    out.push(
      byStart.get(t) ?? { start_ms: t, total: 0, blocked: 0, cache_hits: 0, max_latency_us: 0 },
    );
  }
  return out;
}

function fmt(n: number): string {
  return String(Math.round(n * 10) / 10);
}

function tickLabel(ms: number, spanMs: number): string {
  const d = new Date(ms);
  const hm = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  if (spanMs <= 86_400_000) return hm;
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

/** Turn bucketed counts into SVG path data scaled to the data (queries per bucket). */
export function buildChart(
  points: readonly SeriesPoint[],
  from: number,
  to: number,
  bucketSecs: number,
): ChartModel {
  const bucketMs = bucketSecs * 1000;
  const rows = fillBuckets(points, from, to, bucketMs).map((p) => ({
    start: p.start_ms,
    total: p.total,
    cacheHits: p.cache_hits,
    blocked: p.blocked,
  }));
  const max = niceCeil(Math.max(0, ...rows.map((r) => r.total)));
  const { width, height, left, right, top, bottom } = CHART;
  const plotW = width - left - right;
  const plotH = height - top - bottom;
  const first = rows.length ? rows[0].start : from;
  const span = Math.max(to - first, 1);
  const x = (t: number) => left + ((t - first + bucketMs / 2) / span) * plotW;
  const y = (v: number) => top + plotH - (v / max) * plotH;
  const line = (pick: (r: (typeof rows)[number]) => number) =>
    rows.map((r, i) => `${i ? 'L' : 'M'}${fmt(x(r.start))} ${fmt(y(pick(r)))}`).join(' ');
  const totalPath = line((r) => r.total);
  const cachePath = line((r) => r.cacheHits);
  const totalArea = rows.length
    ? `${totalPath} L${fmt(x(rows[rows.length - 1].start))} ${fmt(top + plotH)} L${fmt(x(rows[0].start))} ${fmt(top + plotH)} Z`
    : '';
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => ({
    label: f === 0 ? '0' : compact(max * f),
    pos: y(max * f),
  }));
  const spanMs = to - from;
  const xTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => ({
    label: tickLabel(from + spanMs * f, spanMs),
    pos: left + f * plotW,
  }));
  return { totalPath, totalArea, cachePath, yTicks, xTicks, max, rows };
}

function compact(n: number): string {
  return n >= 1000 ? `${fmt(n / 1000)}K` : fmt(n);
}

/** Plain-language summary used as the chart's accessible name. */
export function describeChart(model: ChartModel, rangeLabel: string): string {
  const total = model.rows.reduce((s, r) => s + r.total, 0);
  const peak = model.rows.reduce((m, r) => (r.total > m.total ? r : m), model.rows[0]);
  if (!peak || total === 0) return `Queries over the last ${rangeLabel}: no queries.`;
  return `Queries over the last ${rangeLabel}: ${total} in total, peaking at ${peak.total} per bucket at ${new Date(peak.start).toLocaleString()}.`;
}
