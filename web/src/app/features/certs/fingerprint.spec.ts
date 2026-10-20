import { expiryFromDate, parseFingerprint } from './fingerprint';

const HEX = 'ab'.repeat(32);

describe('fingerprint', () => {
  it('normalises colons, spaces and case', () => {
    const colon = HEX.toUpperCase().match(/../g)!.join(':');
    expect(parseFingerprint(colon)).toEqual({ value: HEX });
    expect(parseFingerprint(` ${HEX} `)).toEqual({ value: HEX });
  });
  it('rejects empty, non-hex and wrong length', () => {
    expect(parseFingerprint('')).toHaveProperty('error');
    expect(parseFingerprint('zz'.repeat(32))).toHaveProperty('error');
    expect(parseFingerprint('ab')).toHaveProperty('error');
  });
  it('converts expiry dates', () => {
    expect(expiryFromDate('')).toBeNull();
    expect(expiryFromDate('1970-01-02')).toBe(86400 + 86399);
    expect(expiryFromDate('tomorrow')).toBe('invalid');
    expect(expiryFromDate('2026-13-45')).toBe('invalid');
  });
});
