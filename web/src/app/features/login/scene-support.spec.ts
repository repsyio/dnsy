import {
  cappedPixelRatio,
  decideScene,
  detectWebGl,
  fallbackGrid,
  retrySeconds,
} from './scene-support';

describe('scene-support', () => {
  it('uses webgl only without reduced motion', () => {
    expect(decideScene(false, true)).toBe('webgl');
    expect(decideScene(true, true)).toBe('static');
    expect(decideScene(false, false)).toBe('static');
  });

  it('detects missing and throwing WebGL', () => {
    const doc = (getContext: () => unknown) =>
      ({ createElement: () => ({ getContext }) }) as unknown as Document;
    expect(detectWebGl(doc(() => null))).toBe(false);
    expect(
      detectWebGl(
        doc(() => {
          throw new Error('blocked');
        }),
      ),
    ).toBe(false);
    expect(detectWebGl(doc(() => ({ getExtension: () => null })))).toBe(true);
  });

  it('caps the pixel ratio at 2', () => {
    expect(cappedPixelRatio(3)).toBe(2);
    expect(cappedPixelRatio(1.5)).toBe(1.5);
    expect(cappedPixelRatio(0)).toBe(1);
  });

  it('rounds retry seconds up, minimum one', () => {
    expect(retrySeconds(2.2)).toBe(3);
    expect(retrySeconds(0)).toBe(1);
    expect(retrySeconds(undefined)).toBe(1);
  });

  it('builds a grid below the horizon', () => {
    const { fan, rows } = fallbackGrid();
    expect(fan).toHaveLength(17);
    expect(rows.every((y) => y > 50 && y <= 100)).toBe(true);
  });
});
