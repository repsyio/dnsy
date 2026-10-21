import { InjectionToken } from '@angular/core';
import { type LoginScene, type SceneOptions, createLoginScene } from './login-scene';

/** Creates the login canvas scene; replaced in tests. */
export type SceneFactory = (canvas: HTMLCanvasElement, options: SceneOptions) => LoginScene;

export const LOGIN_SCENE_FACTORY = new InjectionToken<SceneFactory>('LOGIN_SCENE_FACTORY', {
  providedIn: 'root',
  factory: () => createLoginScene,
});
