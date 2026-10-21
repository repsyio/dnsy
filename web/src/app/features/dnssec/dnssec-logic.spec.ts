import {
  algorithmName,
  digestName,
  isWeakening,
  keyTimers,
  normalizeNta,
  nsec3Error,
  ntaError,
  ntaExpiresAt,
  ntaExpiryError,
  orderDs,
  preferredDs,
} from './dnssec-logic';
import type { DsRecord } from './dnssec.service';

const ds = (digest_type: number, key_tag = 1): DsRecord => ({
  key_id: 1,
  key_tag,
  algorithm: 13,
  digest_type,
  digest: 'AB',
  record: `ex. IN DS ${key_tag} 13 ${digest_type} AB`,
});

describe('dnssec logic', () => {
  it('ds_copy_uses_sha256_first', () => {
    const list = [ds(4), ds(2)];
    expect(orderDs(list).map((d) => d.digest_type)).toEqual([2, 4]);
    expect(preferredDs(list)?.digest_type).toBe(2);
    expect(preferredDs([])).toBeNull();
    expect(orderDs([ds(1), ds(4), ds(2)]).map((d) => d.digest_type)).toEqual([2, 4, 1]);
  });

  it('names algorithms and digests', () => {
    expect(algorithmName(15)).toContain('Ed25519');
    expect(algorithmName(8)).toBe('algorithm 8');
    expect(digestName(2)).toBe('SHA-256');
    expect(digestName(4)).toBe('SHA-384');
    expect(digestName(1)).toBe('digest 1');
  });

  it('validates NSEC3 params', () => {
    expect(nsec3Error('', '0', false)).toBeNull();
    expect(nsec3Error('', '', false)).toBeNull();
    expect(nsec3Error('ab12', '0', false)).toBeNull();
    expect(nsec3Error('abc', '0', false)).toContain('hexadecimal');
    expect(nsec3Error('ab'.repeat(256), '0', false)).toContain('255');
    expect(nsec3Error('', 'x', false)).toContain('whole number');
    expect(nsec3Error('', '5', false)).toContain('RFC 9276');
    expect(nsec3Error('', '5', true)).toBeNull();
  });

  it('validates NTA names', () => {
    expect(normalizeNta(' Broken.Example ')).toBe('broken.example.');
    expect(normalizeNta('')).toBe('');
    expect(ntaError('', [])).toContain('Enter');
    expect(ntaError('.', [])).toContain('root');
    expect(ntaError('a..b', [])).toContain('labels');
    expect(ntaError('a b.example', [])).toContain('labels');
    expect(ntaError('x'.repeat(64) + '.example', [])).toContain('labels');
    expect(ntaError(('a'.repeat(60) + '.').repeat(5), [])).toContain('too long');
    expect(ntaError('Broken.example', ['broken.example.'])).toContain('already');
    expect(ntaError('ok.example', [])).toBeNull();
  });

  it('orders validation modes by strength', () => {
    expect(isWeakening('strict', 'permissive')).toBe(true);
    expect(isWeakening('permissive', 'off')).toBe(true);
    expect(isWeakening('off', 'strict')).toBe(false);
    expect(isWeakening('strict', 'strict')).toBe(false);
  });

  it('lists only present key timers', () => {
    expect(keyTimers({ created_at: 1, active_at: 2, published_at: null })).toEqual([
      { label: 'Created', at: 1 },
      { label: 'Active', at: 2 },
    ]);
  });
});

describe('negative trust anchor expiry', () => {
  it('accepts whole hours or nothing', () => {
    expect(ntaExpiryError('')).toBeNull();
    expect(ntaExpiryError(' 24 ')).toBeNull();
    for (const bad of ['0', '-1', '1.5', 'x', '8761']) {
      expect(ntaExpiryError(bad), bad).toContain('whole number of hours');
    }
  });

  it('computes the expiry from the clock', () => {
    expect(ntaExpiresAt('', 1000)).toBeNull();
    expect(ntaExpiresAt('2', 1000)).toBe(1000 + 7200);
  });
});
