import {
  AdditiveBlending,
  BoxGeometry,
  CircleGeometry,
  Color,
  Fog,
  GridHelper,
  Group,
  Mesh,
  MeshBasicMaterial,
  PerspectiveCamera,
  Scene,
  Sprite,
  SpriteMaterial,
  TextureLoader,
  TorusGeometry,
  WebGLRenderer,
  type BufferGeometry,
  type Material,
  type Object3D,
  type Texture,
} from 'three';
import { cappedPixelRatio } from './scene-support';

const CYAN = 0x19e6ff;
const ORANGE = 0xff8a1f;
const BG = 0x05080d;
const CELL = 4;
const MASCOT_URL = 'mascot/nox-idle.svg';

export interface LoginScene {
  dispose(): void;
}

interface Cycle {
  mesh: Mesh;
  speed: number;
  length: number;
}

/** Light-grid floor, light-cycle trails and a hovering Nox hologram. Owns every GPU resource it makes. */
export function createLoginScene(canvas: HTMLCanvasElement): LoginScene {
  const renderer = new WebGLRenderer({ canvas, antialias: true });
  renderer.setPixelRatio(cappedPixelRatio(window.devicePixelRatio));
  renderer.setClearColor(BG);

  const scene = new Scene();
  scene.fog = new Fog(BG, 20, 110);
  const camera = new PerspectiveCamera(60, 1, 0.1, 200);
  camera.position.set(0, 3, 14);

  const grid = new GridHelper(400, 100, CYAN, new Color(CYAN).multiplyScalar(0.35));
  grid.position.z = -100;
  scene.add(grid);

  const sun = new Mesh(
    new CircleGeometry(22, 48),
    new MeshBasicMaterial({ color: ORANGE, transparent: true, opacity: 0.18, fog: false }),
  );
  sun.position.set(0, 12, -120);
  scene.add(sun);

  const cycles: Cycle[] = [];
  for (let i = 0; i < 10; i++) {
    const length = 6 + (i % 4) * 4;
    const mesh = new Mesh(
      new BoxGeometry(0.12, 0.12, length),
      new MeshBasicMaterial({ color: i % 3 === 0 ? ORANGE : CYAN }),
    );
    const lane = (i - 4.5) * CELL * 1.5;
    mesh.position.set(lane, 0.1, -((i * 37) % 120));
    scene.add(mesh);
    cycles.push({ mesh, speed: 14 + (i % 5) * 5, length });
  }

  const holo = new Group();
  holo.position.set(6, 2.6, -6);
  const ring = new Mesh(
    new TorusGeometry(1.8, 0.03, 8, 64),
    new MeshBasicMaterial({ color: CYAN, blending: AdditiveBlending, transparent: true }),
  );
  ring.rotation.x = Math.PI / 2;
  ring.position.y = -1.7;
  holo.add(ring);
  let texture: Texture | null = null;
  let disposed = false;
  new TextureLoader().load(
    MASCOT_URL,
    (t) => {
      if (disposed) {
        t.dispose();
        return;
      }
      texture = t;
      const sprite = new Sprite(
        new SpriteMaterial({ map: t, blending: AdditiveBlending, transparent: true, fog: false }),
      );
      sprite.scale.set(4, 4, 1);
      holo.add(sprite);
    },
    undefined,
    () => undefined, // the hologram is decoration; the scene works without it
  );
  scene.add(holo);

  const pointer = { x: 0, y: 0 };
  const onPointer = (e: PointerEvent): void => {
    pointer.x = (e.clientX / window.innerWidth) * 2 - 1;
    pointer.y = (e.clientY / window.innerHeight) * 2 - 1;
  };
  const resize = (): void => {
    const w = canvas.clientWidth || window.innerWidth;
    const h = canvas.clientHeight || window.innerHeight;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  };

  let last = performance.now();
  let t = 0;
  const frame = (now: number): void => {
    const dt = Math.min((now - last) / 1000, 0.1);
    last = now;
    t += dt;
    grid.position.z += dt * 6;
    if (grid.position.z > -100 + CELL) grid.position.z = -100;
    for (const c of cycles) {
      c.mesh.position.z += c.speed * dt;
      if (c.mesh.position.z - c.length / 2 > 16) c.mesh.position.z = -150;
    }
    holo.position.y = 2.6 + Math.sin(t * 1.2) * 0.2;
    ring.rotation.z = t * 0.6;
    const tx = Math.sin(t * 0.12) * 1.5 + pointer.x * 2.5;
    const ty = 3 + Math.sin(t * 0.17) * 0.4 - pointer.y * 0.8;
    camera.position.x += (tx - camera.position.x) * Math.min(dt * 2, 1);
    camera.position.y += (ty - camera.position.y) * Math.min(dt * 2, 1);
    camera.lookAt(0, 3, -40);
    renderer.render(scene, camera);
  };
  const start = (): void => {
    last = performance.now();
    renderer.setAnimationLoop(frame);
  };
  const onVisibility = (): void => {
    if (document.hidden) renderer.setAnimationLoop(null);
    else start();
  };

  resize();
  window.addEventListener('resize', resize);
  window.addEventListener('pointermove', onPointer, { passive: true });
  document.addEventListener('visibilitychange', onVisibility);
  if (!document.hidden) start();

  return {
    dispose(): void {
      disposed = true;
      renderer.setAnimationLoop(null);
      window.removeEventListener('resize', resize);
      window.removeEventListener('pointermove', onPointer);
      document.removeEventListener('visibilitychange', onVisibility);
      scene.traverse((o: Object3D) => {
        const obj = o as Object3D & { geometry?: BufferGeometry; material?: Material | Material[] };
        obj.geometry?.dispose();
        for (const m of [obj.material ?? []].flat()) m.dispose();
      });
      texture?.dispose();
      renderer.dispose();
      renderer.forceContextLoss();
    },
  };
}
