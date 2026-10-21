/** Device pixel ratio is capped so high-density screens do not quadruple the fill cost. */
export const MAX_PIXEL_RATIO = 2;

export function cappedPixelRatio(dpr: number): number {
  return Math.min(Math.max(dpr, 1), MAX_PIXEL_RATIO);
}

/** The login canvas stops animating after this long without pointer or keyboard activity. */
export const IDLE_PAUSE_MS = 30_000;

/** Seconds the form stays locked after a 429, rounded up and never below one. */
export function retrySeconds(problemRetryAfter: number | null | undefined): number {
  return Math.max(1, Math.ceil(problemRetryAfter ?? 1));
}
