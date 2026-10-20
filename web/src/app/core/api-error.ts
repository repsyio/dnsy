/** RFC 9457 problem document as sent by the API (see `Problem` in openapi/dnsy.json). */
export interface Problem {
  type: string;
  title: string;
  status: number;
  detail: string;
  retry_after_secs?: number;
}

/** Typed error thrown for every failed API call. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly problem: Problem | null,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }

  /** Short machine-readable problem kind, e.g. `unauthorized` (last segment of `type`). */
  get kind(): string {
    return this.problem?.type.split('/').pop() ?? 'unknown';
  }
}

export function isProblem(value: unknown): value is Problem {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v['type'] === 'string' &&
    typeof v['title'] === 'string' &&
    typeof v['status'] === 'number' &&
    typeof v['detail'] === 'string'
  );
}
