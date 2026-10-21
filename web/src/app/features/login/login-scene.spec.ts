import { createLoginScene } from './login-scene';

/** A recording stand-in for CanvasRenderingContext2D (jsdom has no canvas). */
function fakeContext() {
  const strokes: string[] = [];
  const ctx = {
    strokeStyle: '',
    globalAlpha: 1,
    lineWidth: 1,
    setTransform: vi.fn(),
    clearRect: vi.fn(),
    beginPath: vi.fn(),
    moveTo: vi.fn(),
    lineTo: vi.fn(),
    stroke: vi.fn(() => strokes.push(String(ctx.strokeStyle))),
  };
  return { ctx, strokes };
}

describe('createLoginScene', () => {
  let frames: Map<number, FrameRequestCallback>;
  let nextId: number;
  let now: number;
  let fake: ReturnType<typeof fakeContext>;
  let canvas: HTMLCanvasElement;

  const setHidden = (hidden: boolean): void => {
    Object.defineProperty(document, 'hidden', { value: hidden, configurable: true });
    document.dispatchEvent(new Event('visibilitychange'));
  };
  /** Run the pending animation frame `ms` after the current clock. */
  const tick = (ms = 16): void => {
    now += ms;
    const pending = [...frames.entries()];
    frames.clear();
    for (const [, cb] of pending) cb(now);
  };

  beforeEach(() => {
    frames = new Map();
    nextId = 1;
    now = 1000;
    vi.spyOn(performance, 'now').mockImplementation(() => now);
    vi.stubGlobal('requestAnimationFrame', (cb: FrameRequestCallback) => {
      frames.set(nextId, cb);
      return nextId++;
    });
    vi.stubGlobal('cancelAnimationFrame', (id: number) => frames.delete(id));
    vi.stubGlobal('devicePixelRatio', 3);
    fake = fakeContext();
    canvas = document.createElement('canvas');
    canvas.style.setProperty('--dnsy-text', 'white');
    canvas.style.setProperty('--dnsy-red', 'red');
    Object.defineProperty(canvas, 'clientWidth', { value: 800 });
    Object.defineProperty(canvas, 'clientHeight', { value: 600 });
    vi.spyOn(canvas, 'getContext').mockReturnValue(fake.ctx as unknown as CanvasRenderingContext2D);
    document.body.appendChild(canvas);
  });

  afterEach(() => {
    canvas.remove();
    Object.defineProperty(document, 'hidden', { value: false, configurable: true });
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('caps the pixel ratio when sizing the backing store', () => {
    const scene = createLoginScene(canvas, { reducedMotion: false });
    expect(canvas.width).toBe(1600);
    expect(canvas.height).toBe(1200);
    expect(fake.ctx.setTransform).toHaveBeenCalledWith(2, 0, 0, 2, 0, 0);
    scene.dispose();
  });

  it('reduced_motion_draws_a_single_still_frame_without_pulses', () => {
    const scene = createLoginScene(canvas, { reducedMotion: true, random: () => 0 });
    expect(frames.size).toBe(0);
    expect(fake.ctx.clearRect).toHaveBeenCalledTimes(1);
    // five depth buckets in white hairlines, no red pulse pass
    expect(fake.strokes).toHaveLength(5);
    expect(fake.strokes.every((s) => s === 'white')).toBe(true);
    expect(fake.ctx.moveTo).toHaveBeenCalled();
    tick(5000);
    expect(fake.ctx.clearRect).toHaveBeenCalledTimes(1);
    scene.dispose();
  });

  it('hidden_tab_pauses_and_visible_resumes', () => {
    const scene = createLoginScene(canvas, { reducedMotion: false });
    expect(frames.size).toBe(1);
    tick();
    expect(frames.size).toBe(1);

    setHidden(true);
    expect(frames.size).toBe(0);
    const drawn = fake.ctx.clearRect.mock.calls.length;
    tick(1000);
    expect(fake.ctx.clearRect.mock.calls.length).toBe(drawn);

    setHidden(false);
    expect(frames.size).toBe(1);
    tick();
    expect(fake.ctx.clearRect.mock.calls.length).toBe(drawn + 1);
    scene.dispose();
  });

  it('draws several concurrent red pulses while animating', () => {
    const scene = createLoginScene(canvas, { reducedMotion: false, random: () => 0 });
    for (let i = 0; i < 20; i++) tick(50);
    expect(fake.strokes.filter((s) => s === 'red').length).toBeGreaterThan(0);
    scene.dispose();
  });

  it('pauses after 30 s without activity and resumes on pointer movement', () => {
    const scene = createLoginScene(canvas, { reducedMotion: false });
    tick(30_001);
    expect(frames.size).toBe(0);
    window.dispatchEvent(new Event('pointermove'));
    expect(frames.size).toBe(1);
    tick();
    expect(frames.size).toBe(1);
    scene.dispose();
  });

  it('pauses while the password field has focus', () => {
    const scene = createLoginScene(canvas, { reducedMotion: false });
    const password = document.createElement('input');
    password.type = 'password';
    document.body.appendChild(password);
    password.focus();
    expect(frames.size).toBe(0);
    password.blur();
    expect(frames.size).toBe(1);
    password.remove();
    scene.dispose();
  });

  it('dispose stops the loop and ignores later events', () => {
    const scene = createLoginScene(canvas, { reducedMotion: false });
    scene.dispose();
    expect(frames.size).toBe(0);
    setHidden(false);
    window.dispatchEvent(new Event('pointermove'));
    expect(frames.size).toBe(0);
  });

  it('does nothing without a 2D context', () => {
    vi.spyOn(canvas, 'getContext').mockReturnValue(null);
    const scene = createLoginScene(canvas, { reducedMotion: false });
    expect(frames.size).toBe(0);
    scene.dispose();
  });
});
