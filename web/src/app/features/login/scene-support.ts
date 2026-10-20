/** How the login backdrop is drawn. */
export type SceneMode = 'webgl' | 'static';

/** Reduced motion or missing WebGL both select the static SVG grid. */
export function decideScene(reducedMotion: boolean, webgl: boolean): SceneMode {
  return !reducedMotion && webgl ? 'webgl' : 'static';
}

/** True when a WebGL context can be created; probes with a throwaway canvas. */
export function detectWebGl(doc: Document): boolean {
  try {
    const canvas = doc.createElement('canvas');
    const gl = canvas.getContext('webgl2') ?? canvas.getContext('webgl');
    gl?.getExtension('WEBGL_lose_context')?.loseContext();
    return gl !== null && gl !== undefined;
  } catch {
    return false;
  }
}

/** Device pixel ratio is capped so high-density screens do not quadruple the fill cost. */
export const MAX_PIXEL_RATIO = 2;

export function cappedPixelRatio(dpr: number): number {
  return Math.min(Math.max(dpr, 1), MAX_PIXEL_RATIO);
}

/** Seconds the form stays locked after a 429, rounded up and never below one. */
export function retrySeconds(problemRetryAfter: number | null | undefined): number {
  return Math.max(1, Math.ceil(problemRetryAfter ?? 1));
}

/** Perspective grid for the static fallback, in a 0..100 viewBox with the horizon at y = 50. */
export function fallbackGrid(): { fan: number[]; rows: number[] } {
  const fan: number[] = [];
  for (let i = -8; i <= 8; i++) fan.push(50 + i * 14);
  const rows: number[] = [];
  for (let i = 1; i <= 9; i++) rows.push(50 + 50 * (i / 9) ** 2);
  return { fan, rows };
}
