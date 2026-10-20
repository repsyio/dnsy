import { DestroyRef, Signal, inject, signal } from '@angular/core';

const QUERY = '(prefers-reduced-motion: reduce)';

/** Tracks `prefers-reduced-motion`; false where `matchMedia` is unavailable. */
export function injectReducedMotion(): Signal<boolean> {
  const state = signal(false);
  if (typeof matchMedia !== 'function') return state;
  const query = matchMedia(QUERY);
  state.set(query.matches);
  const onChange = (event: MediaQueryListEvent): void => state.set(event.matches);
  query.addEventListener('change', onChange);
  inject(DestroyRef).onDestroy(() => query.removeEventListener('change', onChange));
  return state;
}
