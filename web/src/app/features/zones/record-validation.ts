export const RECORD_TYPES = ['A', 'AAAA', 'NS', 'CNAME', 'PTR', 'MX', 'TXT', 'SRV', 'CAA'] as const;
export type RecordType = (typeof RECORD_TYPES)[number];

const MAX_TTL = 2_147_483_647;
const LABEL_RE = /^[A-Za-z0-9_*]([A-Za-z0-9_-]*[A-Za-z0-9_])?$/;

export interface RecordDraft {
  name: string;
  type: string;
  ttl: string;
  value: string;
}

export type DraftErrors = Partial<Record<'name' | 'type' | 'ttl' | 'value', string>>;

/** Validate a domain name in presentation form: `@`, relative or absolute (trailing dot). */
export function validateName(name: string, allowApex: boolean): string | null {
  const n = name.trim();
  if (!n) return 'Required.';
  if (n === '@') return allowApex ? null : 'Enter a host name.';
  const body = n.endsWith('.') ? n.slice(0, -1) : n;
  if (!body) return n === '.' && allowApex ? null : 'Invalid name.';
  if (n.length > 253) return 'At most 253 characters.';
  for (const label of body.split('.')) {
    if (!label) return 'Empty label.';
    if (label.length > 63) return 'Labels are at most 63 characters.';
    if (!LABEL_RE.test(label)) return `Invalid label "${label}".`;
  }
  return null;
}

export function isIpv4(v: string): boolean {
  const parts = v.split('.');
  return parts.length === 4 && parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}

export function isIpv6(v: string): boolean {
  if (!/^[0-9A-Fa-f:.]+$/.test(v) || v.includes(':::')) return false;
  const halves = v.split('::');
  if (halves.length > 2) return false;
  const groups = (s: string): string[] => (s ? s.split(':') : []);
  const all = halves.flatMap(groups);
  let count = all.length;
  const last = all.at(-1);
  if (last?.includes('.')) {
    if (!isIpv4(last)) return false;
    all.pop();
    count += 1;
  }
  if (!all.every((g) => /^[0-9A-Fa-f]{1,4}$/.test(g))) return false;
  return halves.length === 2 ? count < 8 : count === 8;
}

function uint(v: string, max: number): boolean {
  return /^\d+$/.test(v) && Number(v) <= max;
}

function validateValue(type: string, raw: string): string | null {
  const value = raw.trim();
  if (!value) return 'Required.';
  const f = value.split(/\s+/);
  switch (type) {
    case 'A':
      return isIpv4(value) ? null : 'Enter an IPv4 address, e.g. 192.0.2.1.';
    case 'AAAA':
      return isIpv6(value) ? null : 'Enter an IPv6 address, e.g. 2001:db8::1.';
    case 'NS':
    case 'CNAME':
    case 'PTR':
      return validateName(value, false) ? 'Enter a host name, e.g. ns1.example.com.' : null;
    case 'MX':
      if (f.length !== 2 || !uint(f[0], 65535) || validateName(f[1], false)) {
        return 'Use "<preference 0-65535> <host>", e.g. 10 mail.example.com.';
      }
      return null;
    case 'TXT':
      return value.length > 4096 ? 'At most 4096 characters.' : null;
    case 'SRV':
      if (
        f.length !== 4 ||
        !uint(f[0], 65535) ||
        !uint(f[1], 65535) ||
        !uint(f[2], 65535) ||
        validateName(f[3], false)
      ) {
        return 'Use "<priority> <weight> <port> <target>", e.g. 10 5 5060 sip.example.com.';
      }
      return null;
    case 'CAA':
      if (f.length < 3 || !uint(f[0], 255) || !/^[A-Za-z0-9]+$/.test(f[1])) {
        return 'Use "<flags 0-255> <tag> <value>", e.g. 0 issue "letsencrypt.org".';
      }
      return null;
    default:
      return null;
  }
}

/** Client-side validation of a record form; an empty object means valid. */
export function validateRecord(d: RecordDraft): DraftErrors {
  const errors: DraftErrors = {};
  const nameErr = validateName(d.name, true);
  if (nameErr) errors.name = nameErr;
  if (!(RECORD_TYPES as readonly string[]).includes(d.type)) {
    errors.type = 'Unsupported record type.';
  } else {
    const valueErr = validateValue(d.type, d.value);
    if (valueErr) errors.value = valueErr;
  }
  const ttl = d.ttl.trim();
  if (ttl && !uint(ttl, MAX_TTL)) errors.ttl = `Whole seconds, 0 to ${MAX_TTL}.`;
  return errors;
}
