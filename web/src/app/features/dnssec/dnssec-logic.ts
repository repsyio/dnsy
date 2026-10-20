import type { DsRecord, ValidationMode } from './dnssec.service';

export const ALGORITHMS = [
  { id: 13, label: 'ECDSAP256SHA256 (13)' },
  { id: 15, label: 'Ed25519 (15)' },
] as const;

export function algorithmName(id: number): string {
  return ALGORITHMS.find((a) => a.id === id)?.label ?? `algorithm ${id}`;
}

/** DS records with SHA-256 (digest type 2) first, then SHA-384, then the rest; stable. */
export function orderDs(ds: readonly DsRecord[]): DsRecord[] {
  const rank = (d: DsRecord) => (d.digest_type === 2 ? 0 : d.digest_type === 4 ? 1 : 2);
  return [...ds].sort((a, b) => rank(a) - rank(b));
}

/** The record to paste into a registrar form: the first SHA-256 DS, else the first one. */
export function preferredDs(ds: readonly DsRecord[]): DsRecord | null {
  return orderDs(ds)[0] ?? null;
}

export function digestName(type: number): string {
  return type === 2 ? 'SHA-256' : type === 4 ? 'SHA-384' : `digest ${type}`;
}

/** Message for an invalid NSEC3 salt or iteration count, or null when fine. */
export function nsec3Error(salt: string, iterations: string, allowNonzero: boolean): string | null {
  const s = salt.trim();
  if (s !== '' && !/^([0-9a-fA-F]{2})+$/.test(s)) {
    return 'The salt must be an even number of hexadecimal digits, or empty.';
  }
  if (s.length > 510) return 'The salt is at most 255 bytes.';
  const n = iterations.trim() === '' ? 0 : Number(iterations);
  if (!Number.isInteger(n) || n < 0) return 'Iterations must be a whole number.';
  if (n > 0 && !allowNonzero) {
    return 'RFC 9276 requires 0 iterations; tick "Allow non-zero iterations" to override.';
  }
  return null;
}

/** Message for an invalid negative trust anchor name, or null when fine. */
export function ntaError(raw: string, existing: readonly string[]): string | null {
  const name = normalizeNta(raw);
  if (name === '') return 'Enter a domain name.';
  if (name === '.') return 'The root cannot be an anchor; set validation to off instead.';
  const body = name.slice(0, -1);
  if (name.length > 254) return 'The name is too long.';
  const labels = body.split('.');
  if (labels.some((l) => l.length === 0 || l.length > 63 || !/^[a-z0-9_-]+$/.test(l))) {
    return 'Use labels of letters, digits, hyphen or underscore, at most 63 characters each.';
  }
  if (existing.some((e) => normalizeNta(e) === name)) return `${name} is already listed.`;
  return null;
}

export function normalizeNta(raw: string): string {
  const n = raw.trim().toLowerCase();
  return n === '' || n.endsWith('.') ? n : `${n}.`;
}

const STRENGTH: Record<ValidationMode, number> = { off: 0, permissive: 1, strict: 2 };

export function isWeakening(from: ValidationMode, to: ValidationMode): boolean {
  return STRENGTH[to] < STRENGTH[from];
}

export const MODE_TEXT: Record<ValidationMode, string> = {
  strict:
    'Bogus answers (a failed signature check) become SERVFAIL. Secure answers get the AD bit. Recommended.',
  permissive:
    'Answers are validated and logged, but bogus answers are still returned to clients. Use it to find problems before enforcing.',
  off: 'No validation. Forged answers reach clients unchecked and the AD bit is never set.',
};

export const WEAKEN_TEXT: Record<ValidationMode, string> = {
  strict: '',
  permissive:
    'Permissive mode returns answers that fail validation to clients, so a spoofed or tampered answer is no longer blocked.',
  off: 'With validation off every answer is trusted as received, so spoofed DNS data reaches your clients.',
};

/** Rollover or key timers worth showing, oldest first. */
export function keyTimers(k: {
  created_at: number;
  published_at?: number | null;
  active_at?: number | null;
  retired_at?: number | null;
  removed_at?: number | null;
}): { label: string; at: number }[] {
  const out: { label: string; at: number | null | undefined }[] = [
    { label: 'Created', at: k.created_at },
    { label: 'Published', at: k.published_at },
    { label: 'Active', at: k.active_at },
    { label: 'Retired', at: k.retired_at },
    { label: 'Removed', at: k.removed_at },
  ];
  return out.filter((t): t is { label: string; at: number } => typeof t.at === 'number');
}
