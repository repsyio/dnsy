import { IDLE_PAUSE_MS, cappedPixelRatio, retrySeconds } from './scene-support';

describe('scene-support', () => {
  it('caps the pixel ratio at 2', () => {
    expect(cappedPixelRatio(3)).toBe(2);
    expect(cappedPixelRatio(1.5)).toBe(1.5);
    expect(cappedPixelRatio(0)).toBe(1);
  });

  it('pauses after 30 seconds of inactivity', () => {
    expect(IDLE_PAUSE_MS).toBe(30_000);
  });

  it('rounds retry seconds up, minimum one', () => {
    expect(retrySeconds(2.2)).toBe(3);
    expect(retrySeconds(0)).toBe(1);
    expect(retrySeconds(undefined)).toBe(1);
  });
});
