import {
  BLOB,
  type Pulse,
  bucketAlpha,
  depthBucket,
  icosphere,
  inPulse,
  makeLobes,
  project,
  stepLobes,
  stepPulses,
} from './blob';
import { IDLE_PAUSE_MS, cappedPixelRatio } from './scene-support';

export interface LoginScene {
  dispose(): void;
}

export interface SceneOptions {
  /** Draw one still frame without pulses and never animate. */
  reducedMotion: boolean;
  /** Injected for tests; defaults to Math.random. */
  random?: () => number;
}

/**
 * The login blob on a plain 2D canvas: a morphing wireframe icosphere in white hairlines with red
 * pulses sweeping across it. Animates only while the tab is visible, the visitor is active (pointer
 * tap or keyboard in the last 30 s) and the password field is not focused.
 */
export function createLoginScene(canvas: HTMLCanvasElement, options: SceneOptions): LoginScene {
  const ctx = canvas.getContext('2d');
  if (!ctx) return { dispose: () => undefined };
  const random = options.random ?? Math.random;
  const mesh = icosphere(BLOB.subdivisions);
  const lobes = makeLobes(random);
  const pulses: Pulse[] = [];
  const style = getComputedStyle(canvas);
  const line = style.getPropertyValue('--dnsy-text').trim();
  const red = style.getPropertyValue('--dnsy-red').trim();
  let width = 0;
  let height = 0;
  let t = 0;

  const resize = (): void => {
    const ratio = cappedPixelRatio(window.devicePixelRatio);
    width = canvas.clientWidth;
    height = canvas.clientHeight;
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  };

  const draw = (): void => {
    ctx.clearRect(0, 0, width, height);
    const points = project(mesh, lobes, t, width, height);
    const buckets: number[][] = Array.from({ length: BLOB.buckets }, () => []);
    for (const [a, b] of mesh.edges) {
      buckets[depthBucket((points[a][2] + points[b][2]) / 2)].push(a, b);
    }
    ctx.lineWidth = 0.5;
    ctx.strokeStyle = line;
    buckets.forEach((list, i) => {
      ctx.globalAlpha = bucketAlpha(i);
      ctx.beginPath();
      for (let k = 0; k < list.length; k += 2) {
        const [p, q] = [points[list[k]], points[list[k + 1]]];
        ctx.moveTo(p[0], p[1]);
        ctx.lineTo(q[0], q[1]);
      }
      ctx.stroke();
    });
    if (pulses.length) {
      ctx.strokeStyle = red;
      ctx.globalAlpha = BLOB.pulseAlpha;
      ctx.beginPath();
      for (const pulse of pulses) {
        for (const [a, b] of mesh.edges) {
          if (points[a][2] > BLOB.pulseFront && inPulse(mesh.verts[a], pulse)) {
            ctx.moveTo(points[a][0], points[a][1]);
            ctx.lineTo(points[b][0], points[b][1]);
          }
        }
      }
      ctx.stroke();
    }
    ctx.globalAlpha = 1;
  };

  if (options.reducedMotion) {
    const still = (): void => {
      resize();
      draw();
    };
    still();
    window.addEventListener('resize', still);
    return { dispose: () => window.removeEventListener('resize', still) };
  }

  let handle: number | null = null;
  let last = 0;
  let lastActive = performance.now();
  let passwordFocused = false;

  const frame = (now: number): void => {
    handle = null;
    if (now - lastActive > IDLE_PAUSE_MS) return; // idle: stay paused until the next activity
    const dt = Math.min((now - last) / 1000, 0.1);
    last = now;
    t += dt;
    stepLobes(lobes, dt, random);
    stepPulses(pulses, dt, random);
    draw();
    handle = requestAnimationFrame(frame);
  };
  const stop = (): void => {
    if (handle !== null) cancelAnimationFrame(handle);
    handle = null;
  };
  const sync = (): void => {
    if (document.hidden || passwordFocused) stop();
    else if (handle === null) {
      last = performance.now();
      handle = requestAnimationFrame(frame);
    }
  };
  const onActivity = (): void => {
    lastActive = performance.now();
    sync();
  };
  const onFocus = (e: FocusEvent): void => {
    const password = e.target instanceof HTMLInputElement && e.target.type === 'password';
    if (password) passwordFocused = e.type === 'focusin';
    sync();
  };
  const onResize = (): void => {
    resize();
    if (handle === null) draw();
  };

  resize();
  draw();
  window.addEventListener('resize', onResize);
  window.addEventListener('pointermove', onActivity, { passive: true });
  window.addEventListener('pointerdown', onActivity, { passive: true });
  window.addEventListener('keydown', onActivity);
  document.addEventListener('visibilitychange', sync);
  document.addEventListener('focusin', onFocus);
  document.addEventListener('focusout', onFocus);
  sync();

  return {
    dispose(): void {
      stop();
      window.removeEventListener('resize', onResize);
      window.removeEventListener('pointermove', onActivity);
      window.removeEventListener('pointerdown', onActivity);
      window.removeEventListener('keydown', onActivity);
      document.removeEventListener('visibilitychange', sync);
      document.removeEventListener('focusin', onFocus);
      document.removeEventListener('focusout', onFocus);
    },
  };
}
