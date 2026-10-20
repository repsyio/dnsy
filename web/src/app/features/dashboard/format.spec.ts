import { formatCompact, formatCount, formatLatency, formatRatio, secureRatio } from './format';

describe('format', () => {
  it('cache_hit_ratio_tile_formats', () => {
    expect(formatRatio(0.8734)).toBe('87.3%');
    expect(formatRatio(0)).toBe('0.0%');
    expect(formatRatio(1)).toBe('100.0%');
    expect(formatRatio(null)).toBe('-');
    expect(formatRatio(Number.NaN)).toBe('-');
  });

  it('formats counts and latency units', () => {
    expect(formatCount(1234567)).toBe('1,234,567');
    expect(formatCompact(1500)).toBe('1.5K');
    expect(formatLatency(0)).toBe('-');
    expect(formatLatency(850)).toBe('850 µs');
    expect(formatLatency(12_340)).toBe('12.3 ms');
    expect(formatLatency(2_500_000)).toBe('2.50 s');
  });

  it('secure ratio ignores unchecked answers', () => {
    expect(secureRatio({ unchecked: 50 })).toBeNull();
    expect(secureRatio({ secure: 3, insecure: 1, unchecked: 9 })).toBe(0.75);
    expect(secureRatio({ secure: 1, bogus: 1, indeterminate: 2 })).toBe(0.25);
  });
});
