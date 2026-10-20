import { Injectable, InjectionToken, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { API_BASE, ApiService } from '../../core/api.service';
import { backoffDelay, type LogPage, type LogRecord, type SearchQuery } from './query-log.model';

export const PAGE_SIZE = 100;

/** Creates the `EventSource`; replaced in tests. */
export const EVENT_SOURCE_FACTORY = new InjectionToken<(url: string) => EventSource>(
  'EVENT_SOURCE_FACTORY',
  { providedIn: 'root', factory: () => (url) => new EventSource(url) },
);

export type TailState = 'connecting' | 'live' | 'reconnecting';

export interface TailHandlers {
  record(r: LogRecord): void;
  /** The server skipped rows because this consumer was too slow. */
  lagged(): void;
  state(s: TailState): void;
}

/** Search (keyset pagination) and live tail of the query log. */
@Injectable({ providedIn: 'root' })
export class QueryLogService {
  private readonly api = inject(ApiService);
  private readonly newSource = inject(EVENT_SOURCE_FACTORY);

  search(query: SearchQuery, cursor?: string | null): Observable<LogPage> {
    return this.api.get<LogPage>('/querylog', {
      ...query,
      limit: PAGE_SIZE,
      cursor: cursor ?? undefined,
    });
  }

  /**
   * Open the SSE stream. On error the source is closed and reopened with exponential backoff
   * (the attempt counter resets once a connection opens). Returns a function that stops it.
   */
  tail(query: SearchQuery, h: TailHandlers): () => void {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) params.set(k, String(v));
    const qs = params.toString();
    const url = `${API_BASE}/querylog/stream${qs ? `?${qs}` : ''}`;

    let source: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    let stopped = false;

    const open = (): void => {
      h.state(attempt === 0 ? 'connecting' : 'reconnecting');
      const es = this.newSource(url);
      source = es;
      es.onopen = () => {
        attempt = 0;
        h.state('live');
      };
      es.addEventListener('query', (e) => {
        try {
          h.record(JSON.parse((e as MessageEvent<string>).data) as LogRecord);
        } catch {
          // A malformed event is skipped; the stream carries on.
        }
      });
      es.addEventListener('lagged', () => h.lagged());
      es.onerror = () => {
        es.close();
        if (stopped) return;
        h.state('reconnecting');
        timer = setTimeout(open, backoffDelay(attempt++));
      };
    };
    open();

    return () => {
      stopped = true;
      clearTimeout(timer);
      source?.close();
    };
  }
}
