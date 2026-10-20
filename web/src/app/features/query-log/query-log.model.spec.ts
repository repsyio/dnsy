import {
  DEFAULT_FILTERS,
  backoffDelay,
  formatLatency,
  isDnssecStatus,
  mergeRecords,
  toQuery,
  type LogRecord,
} from './query-log.model';

const NOW = 1_700_000_000_000;
const rec = (id: number): LogRecord => ({
  id,
  ts_ms: id,
  client: 'c',
  transport: 'udp',
  qname: 'a.',
  qtype: 'A',
  rcode: 'NOERROR',
  source: 'cache',
  dnssec: 'secure',
  latency_us: 5,
});

describe('query log model', () => {
  it('filters_serialise_to_query', () => {
    expect(toQuery(DEFAULT_FILTERS, NOW)).toEqual({});
    const q = toQuery(
      {
        ...DEFAULT_FILTERS,
        range: '1h',
        client: ' 10.0.0.1 ',
        domain: 'example',
        qtype: 'AAAA',
        rcode: 'NXDOMAIN',
        source: 'cache_stale',
        dnssec: 'bogus',
      },
      NOW,
    );
    expect(q).toEqual({
      from: NOW - 3_600_000,
      client: '10.0.0.1',
      domain: 'example',
      type: 'AAAA',
      outcome: 'NXDOMAIN',
      source: 'cache_stale',
      dnssec: 'bogus',
    });
  });

  it('serialises a custom range and ignores invalid dates', () => {
    const from = '2026-01-01T10:00';
    const q = toQuery(
      { ...DEFAULT_FILTERS, range: 'custom', customFrom: from, customTo: 'junk' },
      NOW,
    );
    expect(q['from']).toBe(new Date(from).getTime());
    expect(q['to']).toBeUndefined();
  });

  it('omits time bounds for the live tail', () => {
    const q = toQuery({ ...DEFAULT_FILTERS, range: '7d', domain: 'x' }, NOW, false);
    expect(q).toEqual({ domain: 'x' });
  });

  it('merges newest first, drops duplicates and caps', () => {
    const merged = mergeRecords([rec(5), rec(4)], [rec(7), rec(6), rec(5)], 3);
    expect(merged.map((r) => r.id)).toEqual([7, 6, 5]);
  });

  it('backs off exponentially up to a cap', () => {
    expect([0, 1, 2, 3].map(backoffDelay)).toEqual([1000, 2000, 4000, 8000]);
    expect(backoffDelay(20)).toBe(30_000);
  });

  it('formats latency', () => {
    expect(formatLatency(250)).toBe('250 µs');
    expect(formatLatency(1500)).toBe('1.5 ms');
    expect(formatLatency(2_500_000)).toBe('2.50 s');
  });

  it('recognises dnssec statuses', () => {
    expect(isDnssecStatus('secure')).toBe(true);
    expect(isDnssecStatus('weird')).toBe(false);
  });
});
