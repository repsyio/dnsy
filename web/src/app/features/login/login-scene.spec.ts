const h = vi.hoisted(() => ({ disposed: [] as string[], loop: vi.fn(), ratio: vi.fn() }));

vi.mock('three', () => {
  const geo = (n: string) =>
    class {
      dispose = () => h.disposed.push(n);
    };
  const obj = class {
    position = { set: vi.fn(), x: 0, y: 0, z: 0 };
    rotation = { x: 0, z: 0 };
    scale = { set: vi.fn() };
    children: unknown[] = [];
    geometry = { dispose: () => h.disposed.push('geometry') };
    material = { dispose: () => h.disposed.push('material') };
    add(c: unknown) {
      this.children.push(c);
    }
    traverse(fn: (o: unknown) => void) {
      fn(this);
      this.children.forEach((c) => (c as { traverse(f: typeof fn): void }).traverse(fn));
    }
    lookAt = vi.fn();
    updateProjectionMatrix = vi.fn();
  };
  return {
    AdditiveBlending: 2,
    BoxGeometry: geo('box'),
    CircleGeometry: geo('circle'),
    TorusGeometry: geo('torus'),
    Color: class {
      multiplyScalar() {
        return this;
      }
    },
    Fog: class {},
    GridHelper: obj,
    Group: obj,
    Mesh: obj,
    MeshBasicMaterial: class {
      dispose = () => h.disposed.push('material');
    },
    SpriteMaterial: class {},
    Sprite: obj,
    PerspectiveCamera: class extends obj {},
    Scene: obj,
    TextureLoader: class {
      load() {
        /* never resolves */
      }
    },
    WebGLRenderer: class {
      setPixelRatio = h.ratio;
      setClearColor = vi.fn();
      setSize = vi.fn();
      setAnimationLoop = h.loop;
      render = vi.fn();
      dispose = () => h.disposed.push('renderer');
      forceContextLoss = () => h.disposed.push('context');
    },
  };
});

import { createLoginScene } from './login-scene';

describe('createLoginScene', () => {
  it('caps pixel ratio, pauses when hidden and frees GPU resources', () => {
    vi.stubGlobal('devicePixelRatio', 3);
    const scene = createLoginScene(document.createElement('canvas'));
    expect(h.ratio).toHaveBeenCalledWith(2);
    expect(h.loop).toHaveBeenLastCalledWith(expect.any(Function));

    Object.defineProperty(document, 'hidden', { value: true, configurable: true });
    document.dispatchEvent(new Event('visibilitychange'));
    expect(h.loop).toHaveBeenLastCalledWith(null);
    Object.defineProperty(document, 'hidden', { value: false, configurable: true });
    document.dispatchEvent(new Event('visibilitychange'));
    expect(h.loop).toHaveBeenLastCalledWith(expect.any(Function));

    scene.dispose();
    expect(h.loop).toHaveBeenLastCalledWith(null);
    expect(h.disposed).toEqual(
      expect.arrayContaining(['geometry', 'material', 'renderer', 'context']),
    );
    vi.unstubAllGlobals();
  });
});
