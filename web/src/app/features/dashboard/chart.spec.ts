import { CHART, RANGES, buildChart, describeChart, fillBuckets, niceCeil } from './chart';

const HOUR = 3_600_000;

describe('chart', () => {
  it('chart_scales_to_data', () => {
    const from = 0;
    const to = HOUR;
    const pts = [
      { start_ms: 0, total: 40, blocked: 0, cache_hits: 10, max_latency_us: 0 },
      { start_ms: 60_000, total: 90, blocked: 0, cache_hits: 20, max_latency_us: 0 },
    ];
    const c = buildChart(pts, from, to, 60);
    expect(c.max).toBe(100);
    expect(c.rows).toHaveLength(60);
    // the peak (90 of 100) sits at 10% below the top of the plot
    const plotH = CHART.height - CHART.top - CHART.bottom;
    const peakY = CHART.top + plotH - 0.9 * plotH;
    expect(c.totalPath).toContain(`L${Math.round(peakY * 10) / 10}`.replace('L', ' '));
    expect(c.totalPath.startsWith('M')).toBe(true);
    expect(c.totalArea.endsWith('Z')).toBe(true);
    expect(c.yTicks[0].label).toBe('0');
    expect(c.yTicks[4].label).toBe('100');
    expect(c.xTicks).toHaveLength(5);
  });

  it('scales a larger axis in thousands and by day for 7d', () => {
    const c = buildChart(
      [{ start_ms: 0, total: 2500, blocked: 0, cache_hits: 0, max_latency_us: 0 }],
      0,
      RANGES[2].spanMs,
      7200,
    );
    expect(c.max).toBe(5000);
    expect(c.yTicks[4].label).toBe('5K');
    expect(c.xTicks[0].label).toMatch(/^\d+\/\d+$/);
  });

  it('rounds the axis up to a nice number', () => {
    expect(niceCeil(0)).toBe(1);
    expect(niceCeil(1)).toBe(1);
    expect(niceCeil(1.5)).toBe(2);
    expect(niceCeil(3)).toBe(5);
    expect(niceCeil(7)).toBe(10);
    expect(niceCeil(230)).toBe(500);
  });

  it('fills missing buckets with zeros', () => {
    const out = fillBuckets(
      [{ start_ms: 120_000, total: 5, blocked: 1, cache_hits: 2, max_latency_us: 3 }],
      0,
      240_000,
      60_000,
    );
    expect(out.map((p) => p.total)).toEqual([0, 0, 5, 0]);
  });

  it('describes the chart for assistive tech', () => {
    const c = buildChart(
      [{ start_ms: 0, total: 7, blocked: 0, cache_hits: 0, max_latency_us: 0 }],
      0,
      120_000,
      60,
    );
    expect(describeChart(c, '1 hour')).toContain('7 in total, peaking at 7');
    const empty = buildChart([], 0, 120_000, 60);
    expect(describeChart(empty, '1 hour')).toContain('no queries');
    expect(describeChart({ ...empty, rows: [] }, '1 hour')).toContain('no queries');
  });
});
