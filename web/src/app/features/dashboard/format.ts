const COUNT = new Intl.NumberFormat('en-US');
const COMPACT = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 });

/** Whole number with thousands separators. */
export function formatCount(n: number): string {
  return COUNT.format(Math.round(n));
}

/** Compact count for chart axes (`1.2K`). */
export function formatCompact(n: number): string {
  return COMPACT.format(n);
}

/** A 0..1 ratio as a percentage with one decimal; `-` when there is nothing to show. */
export function formatRatio(ratio: number | null | undefined): string {
  if (ratio == null || !Number.isFinite(ratio)) return '-';
  return `${(ratio * 100).toFixed(1)}%`;
}

/** Microseconds as the most readable unit. */
export function formatLatency(us: number): string {
  if (!Number.isFinite(us) || us <= 0) return '-';
  if (us < 1000) return `${Math.round(us)} µs`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(1)} ms`;
  return `${(us / 1_000_000).toFixed(2)} s`;
}

/** Share of validated answers that were secure; unchecked answers do not count. */
export function secureRatio(dnssec: Record<string, number>): number | null {
  const secure = dnssec['secure'] ?? 0;
  const validated =
    secure + (dnssec['insecure'] ?? 0) + (dnssec['bogus'] ?? 0) + (dnssec['indeterminate'] ?? 0);
  return validated === 0 ? null : secure / validated;
}
