/** Normalise a SHA-256 fingerprint (colons, spaces and case ignored) or return an error. */
export function parseFingerprint(input: string): { value: string } | { error: string } {
  const hex = input.replace(/[\s:]/g, '').toLowerCase();
  if (hex === '') return { error: 'Enter the SHA-256 fingerprint.' };
  if (!/^[0-9a-f]+$/.test(hex)) return { error: 'Only hexadecimal digits and colons are allowed.' };
  if (hex.length !== 64) return { error: 'A SHA-256 fingerprint has 64 hex digits.' };
  return { value: hex };
}

/** Unix seconds for a `YYYY-MM-DD` date (end of that day, UTC), or `null` when empty. */
export function expiryFromDate(date: string): number | null | 'invalid' {
  if (date === '') return null;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return 'invalid';
  const ms = Date.parse(`${date}T23:59:59Z`);
  return Number.isNaN(ms) ? 'invalid' : Math.floor(ms / 1000);
}
