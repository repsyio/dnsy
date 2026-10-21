import {
  BLOB,
  type Pulse,
  bucketAlpha,
  depthBucket,
  icosphere,
  inPulse,
  makeLobes,
  morphRadius,
  project,
  randomUnit,
  stepLobes,
  stepPulses,
} from './blob';

/** Deterministic LCG so the statistical checks are stable. */
function seeded(seed = 7): () => number {
  let s = seed;
  return () => {
    s = (s * 1664525 + 1013904223) % 2 ** 32;
    return s / 2 ** 32;
  };
}

describe('blob', () => {
  it('icosphere_level_2_has_162_vertices_and_480_unique_edges', () => {
    const { verts, edges } = icosphere(2);
    expect(verts).toHaveLength(162);
    expect(edges).toHaveLength(480);
    expect(new Set(edges.map(([a, b]) => `${a}_${b}`)).size).toBe(480);
    expect(edges.every(([a, b]) => a < b)).toBe(true);
    expect(verts.every((v) => Math.abs(Math.hypot(...v) - 1) < 1e-9)).toBe(true);
  });

  it('random points lie on the unit sphere', () => {
    const random = seeded();
    for (let i = 0; i < 50; i++) expect(Math.hypot(...randomUnit(random))).toBeCloseTo(1, 9);
  });

  it('morph stays within the strong amplitude', () => {
    const random = seeded();
    const lobes = makeLobes(random);
    expect(lobes).toHaveLength(5);
    const bound = (BLOB.amplitude * BLOB.lobes) / 2.2;
    for (const v of icosphere(2).verts) {
      const r = morphRadius(v, lobes);
      expect(r).toBeGreaterThanOrEqual(1 - bound);
      expect(r).toBeLessThanOrEqual(1 + bound);
    }
  });

  it('lobes drift toward their targets and keep moving', () => {
    const lobes = makeLobes(seeded());
    const before = lobes.map((l) => [...l.d]);
    const phase = lobes[0].phase;
    stepLobes(lobes, 0.1, () => 0.99);
    expect(lobes[0].phase).toBeGreaterThan(phase);
    expect(lobes[0].d).not.toEqual(before[0]);
  });

  it('pulses_start_about_1_2_per_second_and_several_run_at_once', () => {
    const random = seeded(11);
    const pulses: Pulse[] = [];
    const seen = new Set<Pulse>();
    let concurrent = 0;
    let samples = 0;
    const dt = 1 / 60;
    for (let i = 0; i < 60 * 120; i++) {
      stepPulses(pulses, dt, random);
      pulses.forEach((p) => seen.add(p));
      concurrent += pulses.length;
      samples += 1;
    }
    expect(seen.size / 120).toBeGreaterThan(0.9);
    expect(seen.size / 120).toBeLessThan(1.5);
    // each sweep lasts 2.2 / (0.45..0.8) s, so about 3 to 4 run at once on average
    expect(concurrent / samples).toBeGreaterThan(2);
    expect(pulses.every((p) => p.progress <= BLOB.pulseEnd)).toBe(true);
  });

  it('a pulse band moves from the top of its axis to the far side', () => {
    const pulse: Pulse = { axis: [0, 1, 0], progress: 0, speed: 0.5 };
    expect(inPulse([0, 1, 0], pulse)).toBe(false);
    pulse.progress = 0.1;
    expect(inPulse([0, 1, 0], pulse)).toBe(true);
    pulse.progress = 1.1;
    expect(inPulse([1, 0, 0], pulse)).toBe(true);
    expect(inPulse([0, 1, 0], pulse)).toBe(false);
  });

  it('depth buckets span far to near with 0.12 to 0.80 opacity', () => {
    expect(depthBucket(-5)).toBe(0);
    expect(depthBucket(5)).toBe(4);
    expect(depthBucket(0)).toBe(2);
    expect(bucketAlpha(0)).toBeCloseTo(0.12);
    expect(bucketAlpha(4)).toBeCloseTo(0.8);
  });

  it('projects a huge sphere centred near the right edge', () => {
    const mesh = icosphere(0);
    const lobes = makeLobes(seeded()).map((l) => ({ ...l, freq: 0 }));
    lobes.forEach((l) => (l.phase = 0)); // sin(0) = 0: an undeformed sphere
    const points = project(mesh, lobes, 0, 1000, 500);
    const xs = points.map((p) => p[0]);
    const ys = points.map((p) => p[1]);
    const cx = (Math.min(...xs) + Math.max(...xs)) / 2;
    const cy = (Math.min(...ys) + Math.max(...ys)) / 2;
    expect(cx).toBeGreaterThan(900);
    expect(cy).toBeGreaterThan(240);
    expect(Math.max(...ys) - Math.min(...ys)).toBeGreaterThan(500 * 0.9 * 1.5);
  });
});
