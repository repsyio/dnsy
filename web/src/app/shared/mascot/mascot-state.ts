export type MascotState = 'loading' | 'empty' | 'error' | 'success' | 'offline' | 'not-found';
export type MascotSize = 'sm' | 'md' | 'lg';

export const MASCOT_LABELS: Record<MascotState, string> = {
  loading: 'Nox is loading',
  empty: 'Nox found nothing here',
  error: 'Nox reports an error',
  success: 'Nox reports success',
  offline: 'Nox is offline',
  'not-found': 'Nox could not find the page',
};

export const MASCOT_MESSAGES: Record<MascotState, string> = {
  loading: 'Loading...',
  empty: 'Nothing here yet.',
  error: 'Something went wrong.',
  success: 'Done.',
  offline: 'You are offline.',
  'not-found': 'Page not found.',
};

/** Tailwind classes per size; written out so the Tailwind scanner sees them. */
export const MASCOT_SIZES: Record<MascotSize, string> = {
  sm: 'h-16 w-16',
  md: 'h-28 w-28',
  lg: 'h-40 w-40',
};

/** Live-region role of the caption, so assistive tech announces state changes. */
export const MASCOT_ROLES: Record<MascotState, 'status' | 'alert' | null> = {
  loading: 'status',
  empty: null,
  error: 'alert',
  success: 'status',
  offline: 'status',
  'not-found': null,
};
