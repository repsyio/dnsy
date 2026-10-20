import { InjectionToken } from '@angular/core';
import type { LoginScene } from './login-scene';

/** Loads the three.js scene on demand (own chunk); replaced in tests. */
export type SceneLoader = () => Promise<(canvas: HTMLCanvasElement) => LoginScene>;

export const LOGIN_SCENE_LOADER = new InjectionToken<SceneLoader>('LOGIN_SCENE_LOADER', {
  providedIn: 'root',
  factory: () => () => import('./login-scene').then((m) => m.createLoginScene),
});
