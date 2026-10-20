import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, vi } from 'vitest';
import { EVENT_SOURCE_FACTORY, QueryLogService, type TailState } from './query-log.service';

class FakeSource {
  static all: FakeSource[] = [];
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  private readonly listeners = new Map<string, (e: unknown) => void>();
  constructor(readonly url: string) {
    FakeSource.all.push(this);
  }
  addEventListener(name: string, fn: (e: unknown) => void) {
    this.listeners.set(name, fn);
  }
  emit(name: string, data = '') {
    this.listeners.get(name)?.({ data });
  }
  close() {
    this.closed = true;
  }
}

function setup() {
  FakeSource.all = [];
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      { provide: EVENT_SOURCE_FACTORY, useValue: (u: string) => new FakeSource(u) },
    ],
  });
  return { svc: TestBed.inject(QueryLogService), http: TestBed.inject(HttpTestingController) };
}

describe('QueryLogService', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('searches with filters, limit and cursor', () => {
    const { svc, http } = setup();
    svc.search({ domain: 'a', dnssec: 'bogus' }, 'abc').subscribe();
    const req = http.expectOne((r) => r.url === '/api/v1/querylog');
    expect(req.request.params.get('domain')).toBe('a');
    expect(req.request.params.get('cursor')).toBe('abc');
    expect(req.request.params.get('limit')).toBe('100');
    req.flush({ entries: [] });
    svc.search({}).subscribe();
    expect(http.expectOne((r) => r.url === '/api/v1/querylog').request.params.has('cursor')).toBe(
      false,
    );
  });

  it('live_tail_appends records, reports lag and ignores garbage', () => {
    const { svc } = setup();
    const records: number[] = [];
    const states: TailState[] = [];
    let lagged = 0;
    const stop = svc.tail(
      { source: 'blocked' },
      {
        record: (r) => records.push(r.id),
        lagged: () => lagged++,
        state: (s) => states.push(s),
      },
    );
    const es = FakeSource.all[0];
    expect(es.url).toBe('/api/v1/querylog/stream?source=blocked');
    es.onopen?.();
    es.emit('query', '{"id":1}');
    es.emit('query', 'not json');
    es.emit('lagged');
    expect(records).toEqual([1]);
    expect(lagged).toBe(1);
    expect(states).toEqual(['connecting', 'live']);
    stop();
    expect(es.closed).toBe(true);
  });

  it('reconnects with backoff and resets after a successful open', () => {
    const { svc } = setup();
    const states: TailState[] = [];
    const stop = svc.tail(
      {},
      { record: () => undefined, lagged: () => undefined, state: (s) => states.push(s) },
    );
    expect(FakeSource.all[0].url).toBe('/api/v1/querylog/stream');
    FakeSource.all[0].onerror?.();
    expect(FakeSource.all[0].closed).toBe(true);
    vi.advanceTimersByTime(999);
    expect(FakeSource.all.length).toBe(1);
    vi.advanceTimersByTime(1);
    expect(FakeSource.all.length).toBe(2);
    FakeSource.all[1].onerror?.();
    vi.advanceTimersByTime(2000);
    expect(FakeSource.all.length).toBe(3);
    FakeSource.all[2].onopen?.();
    FakeSource.all[2].onerror?.();
    vi.advanceTimersByTime(1000);
    expect(FakeSource.all.length).toBe(4);
    expect(states).toContain('reconnecting');
    stop();
    FakeSource.all[3].onerror?.();
    vi.advanceTimersByTime(60_000);
    expect(FakeSource.all.length).toBe(4);
  });

  it('does not reconnect when stopped before the timer fires', () => {
    const { svc } = setup();
    const stop = svc.tail(
      {},
      { record: () => undefined, lagged: () => undefined, state: () => undefined },
    );
    FakeSource.all[0].onerror?.();
    stop();
    vi.advanceTimersByTime(60_000);
    expect(FakeSource.all.length).toBe(1);
  });
});
