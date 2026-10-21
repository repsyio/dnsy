/**
 * Geometry for the login blob: a morphing wireframe icosphere swept by red pulses. Pure functions
 * (randomness is injected) so the canvas loop in `login-scene.ts` stays thin and testable.
 */
export type Vec3 = [number, number, number];

export interface Mesh {
  verts: Vec3[];
  /** Unique edges as vertex index pairs. */
  edges: [number, number][];
}

/** One lobe of the morph: a direction drifting toward a target, a frequency and a phase. */
export interface Lobe {
  d: Vec3;
  target: Vec3;
  freq: number;
  phase: number;
  speed: number;
}

/** A red band sweeping the surface along `axis`; `progress` runs from 0 to PULSE_END. */
export interface Pulse {
  axis: Vec3;
  progress: number;
  speed: number;
}

export const BLOB = {
  subdivisions: 2,
  /** Radius as a fraction of the canvas height. */
  radius: 0.9,
  /** Centre as fractions of the canvas width and height. */
  centreX: 0.95,
  centreY: 0.55,
  /** Camera distance in radii. */
  camera: 3.2,
  lobes: 5,
  amplitude: 0.34,
  /** Lobe directions ease toward their target at this rate per second. */
  drift: 0.15,
  /** Chance per second that a lobe picks a new target (about every 12 s). */
  retarget: 0.08,
  spinY: 0.12,
  tiltX: 0.35,
  tiltSwing: 0.15,
  tiltRate: 0.07,
  /** Opacity of the far and near depth buckets. */
  farAlpha: 0.12,
  nearAlpha: 0.8,
  buckets: 5,
  /** Mean new pulses per second. */
  pulseRate: 1.2,
  pulseBand: 0.08,
  pulseStart: 1.1,
  pulseEnd: 2.2,
  pulseMinSpeed: 0.45,
  pulseMaxSpeed: 0.8,
  pulseAlpha: 0.85,
  /** Pulses only light edges whose start vertex is in front of this depth. */
  pulseFront: -0.2,
} as const;

const unit = (v: Vec3): Vec3 => {
  const l = Math.hypot(v[0], v[1], v[2]);
  return [v[0] / l, v[1] / l, v[2] / l];
};

const dot = (a: Vec3, b: Vec3): number => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];

/** Icosahedron subdivided `level` times, vertices on the unit sphere. */
export function icosphere(level: number): Mesh {
  const p = (1 + Math.sqrt(5)) / 2;
  const verts: Vec3[] = (
    [
      [-1, p, 0],
      [1, p, 0],
      [-1, -p, 0],
      [1, -p, 0],
      [0, -1, p],
      [0, 1, p],
      [0, -1, -p],
      [0, 1, -p],
      [p, 0, -1],
      [p, 0, 1],
      [-p, 0, -1],
      [-p, 0, 1],
    ] as Vec3[]
  ).map(unit);
  let faces: Vec3[] = [
    [0, 11, 5],
    [0, 5, 1],
    [0, 1, 7],
    [0, 7, 10],
    [0, 10, 11],
    [1, 5, 9],
    [5, 11, 4],
    [11, 10, 2],
    [10, 7, 6],
    [7, 1, 8],
    [3, 9, 4],
    [3, 4, 2],
    [3, 2, 6],
    [3, 6, 8],
    [3, 8, 9],
    [4, 9, 5],
    [2, 4, 11],
    [6, 2, 10],
    [8, 6, 7],
    [9, 8, 1],
  ];
  for (let s = 0; s < level; s++) {
    const cache = new Map<string, number>();
    const mid = (a: number, b: number): number => {
      const key = a < b ? `${a}_${b}` : `${b}_${a}`;
      let i = cache.get(key);
      if (i === undefined) {
        const [va, vb] = [verts[a], verts[b]];
        i = verts.push(unit([va[0] + vb[0], va[1] + vb[1], va[2] + vb[2]])) - 1;
        cache.set(key, i);
      }
      return i;
    };
    faces = faces.flatMap(([a, b, c]) => {
      const [ab, bc, ca] = [mid(a, b), mid(b, c), mid(c, a)];
      return [
        [a, ab, ca],
        [b, bc, ab],
        [c, ca, bc],
        [ab, bc, ca],
      ] as Vec3[];
    });
  }
  const seen = new Set<string>();
  const edges: [number, number][] = [];
  for (const [a, b, c] of faces) {
    for (const [x, y] of [
      [a, b],
      [b, c],
      [c, a],
    ]) {
      const [lo, hi] = x < y ? [x, y] : [y, x];
      const key = `${lo}_${hi}`;
      if (!seen.has(key)) {
        seen.add(key);
        edges.push([lo, hi]);
      }
    }
  }
  return { verts, edges };
}

/** Uniform random point on the unit sphere. */
export function randomUnit(random: () => number): Vec3 {
  const t = random() * 2 * Math.PI;
  const z = random() * 2 - 1;
  const r = Math.sqrt(1 - z * z);
  return [r * Math.cos(t), r * Math.sin(t), z];
}

export function makeLobes(random: () => number): Lobe[] {
  return Array.from({ length: BLOB.lobes }, () => ({
    d: randomUnit(random),
    target: randomUnit(random),
    freq: 1.5 + random() * 2.5,
    phase: random() * 2 * Math.PI,
    speed: 0.25 + random() * 0.5,
  }));
}

/** Advance phases, ease directions toward their targets, and now and then pick a new target. */
export function stepLobes(lobes: Lobe[], dt: number, random: () => number): void {
  for (const lobe of lobes) {
    lobe.phase += lobe.speed * dt;
    for (let i = 0; i < 3; i++) lobe.d[i] += (lobe.target[i] - lobe.d[i]) * dt * BLOB.drift;
    if (random() < dt * BLOB.retarget) lobe.target = randomUnit(random);
  }
}

/** Radius of vertex `v` under the morph: 1 + amplitude * sum(sin(v.d * f + phase)) / 2.2. */
export function morphRadius(v: Vec3, lobes: Lobe[]): number {
  let sum = 0;
  for (const lobe of lobes) sum += Math.sin(dot(v, lobe.d) * lobe.freq + lobe.phase);
  return 1 + (BLOB.amplitude * sum) / 2.2;
}

/** Spawn new pulses at `rate` per second on average, advance all, drop those past the far side. */
export function stepPulses(
  pulses: Pulse[],
  dt: number,
  random: () => number,
  rate: number = BLOB.pulseRate,
): void {
  if (random() < dt * rate) {
    const speed = BLOB.pulseMinSpeed + random() * (BLOB.pulseMaxSpeed - BLOB.pulseMinSpeed);
    pulses.push({ axis: randomUnit(random), progress: 0, speed });
  }
  for (const pulse of pulses) pulse.progress += dt * pulse.speed;
  for (let i = pulses.length - 1; i >= 0; i--) {
    if (pulses[i].progress > BLOB.pulseEnd) pulses.splice(i, 1);
  }
}

/** True when vertex `v` lies in the pulse's band (the band runs from 1.1 down to -1.1). */
export function inPulse(v: Vec3, pulse: Pulse): boolean {
  return Math.abs(dot(v, pulse.axis) - (BLOB.pulseStart - pulse.progress)) < BLOB.pulseBand;
}

/** Depth bucket 0 (far) to 4 (near) for a projected depth in about -1.3..1.3. */
export function depthBucket(z: number): number {
  const i = Math.floor(((z + 1.3) / 2.6) * BLOB.buckets);
  return Math.max(0, Math.min(BLOB.buckets - 1, i));
}

/** Opacity of a depth bucket, evenly spaced from far to near. */
export function bucketAlpha(bucket: number): number {
  return BLOB.farAlpha + ((BLOB.nearAlpha - BLOB.farAlpha) * bucket) / (BLOB.buckets - 1);
}

/** Rotate (spin around y, tilt around x) and project the morphed vertices to canvas pixels. */
export function project(
  mesh: Mesh,
  lobes: Lobe[],
  t: number,
  width: number,
  height: number,
): Vec3[] {
  const ry = t * BLOB.spinY;
  const rx = BLOB.tiltX + Math.sin(t * BLOB.tiltRate) * BLOB.tiltSwing;
  const [cy, sy, cx, sx] = [Math.cos(ry), Math.sin(ry), Math.cos(rx), Math.sin(rx)];
  const radius = height * BLOB.radius;
  const ox = width * BLOB.centreX;
  const oy = height * BLOB.centreY;
  return mesh.verts.map((v) => {
    const r = morphRadius(v, lobes);
    const [x0, y0, z0] = [v[0] * r, v[1] * r, v[2] * r];
    const x = x0 * cy + z0 * sy;
    const z1 = -x0 * sy + z0 * cy;
    const y = y0 * cx - z1 * sx;
    const z = y0 * sx + z1 * cx;
    const s = BLOB.camera / (BLOB.camera - z);
    return [ox + x * radius * s, oy + y * radius * s, z];
  });
}
