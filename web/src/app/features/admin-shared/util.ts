import { ApiError } from '../../core/api-error';

/** Message to show for a failed call: the server's problem detail when there is one. */
export function messageOf(e: unknown, fallback: string): string {
  return e instanceof ApiError ? e.message : fallback;
}

/** Epoch seconds as a short UTC date-time, or a dash when absent. */
export function formatEpoch(secs: number | null | undefined): string {
  if (secs === null || secs === undefined) return '-';
  return new Date(secs * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}
