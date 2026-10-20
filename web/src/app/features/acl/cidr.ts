const OCTET = /^(0|[1-9]\d{0,2})$/;
const HEXTET = /^[0-9a-fA-F]{1,4}$/;

function validV4(host: string): boolean {
  const parts = host.split('.');
  return parts.length === 4 && parts.every((p) => OCTET.test(p) && Number(p) <= 255);
}

function validV6(host: string): boolean {
  if (!host.includes(':') || host.includes(':::')) return false;
  const halves = host.split('::');
  if (halves.length > 2) return false;
  const groups = (s: string): string[] | null => {
    if (s === '') return [];
    const parts = s.split(':');
    const last = parts[parts.length - 1];
    if (last.includes('.')) {
      if (!validV4(last)) return null;
      parts.splice(parts.length - 1, 1, 'x', 'x');
    }
    return parts.every((p) => p === 'x' || HEXTET.test(p)) ? parts : null;
  };
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  if (head === null || tail === null) return false;
  const count = head.length + tail.length;
  return halves.length === 2 ? count <= 7 : count === 8;
}

/** Error text for an IPv4/IPv6 address or CIDR block, or `null` when it is valid. */
export function validateCidr(input: string): string | null {
  const text = input.trim();
  if (text === '') return 'Enter an address or CIDR block.';
  const [host, prefix, ...extra] = text.split('/');
  if (extra.length > 0) return 'Use one "/" between the address and the prefix length.';
  const v4 = validV4(host);
  if (!v4 && !validV6(host)) return 'Not a valid IPv4 or IPv6 address.';
  if (prefix !== undefined) {
    const max = v4 ? 32 : 128;
    if (!/^\d{1,3}$/.test(prefix) || Number(prefix) > max) {
      return `Prefix length must be 0 to ${max}.`;
    }
  }
  return null;
}
