import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { apiInterceptor } from '../../core/api.interceptor';
import { AuthService } from '../../core/auth.service';
import { MAX_ROWS, QueryLogPage } from './query-log.page';
import type { LogRecord } from './query-log.model';
import { EVENT_SOURCE_FACTORY } from './query-log.service';

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

const rec = (id: number, extra: Partial<LogRecord> = {}): LogRecord => ({
  id,
  ts_ms: 1_700_000_000_000 + id,
  client: '10.0.0.1',
  transport: 'udp',
  qname: `h${id}.example.`,
  qtype: 'A',
  rcode: 'NOERROR',
  source: 'upstream',
  dnssec: 'secure',
  latency_us: 800,
  ...extra,
});

function setup(role = 'operator') {
  FakeSource.all = [];
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(withInterceptors([apiInterceptor])),
      provideHttpClientTesting(),
      { provide: EVENT_SOURCE_FACTORY, useValue: (u: string) => new FakeSource(u) },
      { provide: AuthService, useValue: { user: () => ({ username: 'u', role }) } },
    ],
  });
  const fixture = TestBed.createComponent(QueryLogPage);
  const http = TestBed.inject(HttpTestingController);
  const el = fixture.nativeElement as HTMLElement;
  const search = () => http.expectOne((r) => r.url === '/api/v1/querylog');
  const button = (text: string) =>
    Array.from(el.querySelectorAll('button')).find((b) =>
      b.textContent?.trim().startsWith(text),
    ) as HTMLButtonElement;
  const select = (id: string, value: string) => {
    const s = el.querySelector(`#${id}`) as HTMLSelectElement | HTMLInputElement;
    s.value = value;
    s.dispatchEvent(new Event(s instanceof HTMLSelectElement ? 'change' : 'input'));
  };
  return { fixture, http, el, search, button, select };
}

describe('QueryLogPage', () => {
  it('shows loading, then rows with badges', async () => {
    const { fixture, el, search } = setup();
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    search().flush({
      entries: [rec(2, { dnssec: 'bogus', source: 'cache_stale' }), rec(1)],
      next_cursor: null,
    });
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(2);
    expect(el.querySelector('[data-status=bogus]')).not.toBeNull();
    expect(el.textContent).toContain('Stale');
    expect(el.textContent).toContain('End of the log.');
  });

  it('shows the empty and error states, and retries', async () => {
    const { fixture, el, search, button } = setup();
    await fixture.whenStable();
    search().flush({ entries: [] });
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-empty')).not.toBeNull();

    button('Apply').click();
    search().flush(
      { title: 'x', detail: 'boom', status: 500, type: 'about:blank' },
      { status: 500, statusText: 'x' },
    );
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-error')).not.toBeNull();
    (el.querySelector('dnsy-mascot-error button') as HTMLButtonElement).click();
    search().flush({ entries: [rec(1)] });
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(1);
  });

  it('sends filters on apply and clears them on reset', async () => {
    const { fixture, search, button, select } = setup();
    await fixture.whenStable();
    search().flush({ entries: [] });
    select('f-dnssec', 'bogus');
    select('f-source', 'cache_stale');
    select('f-domain', 'evil');
    select('f-range', 'custom');
    await fixture.whenStable();
    select('f-from', '2026-01-01T00:00');
    button('Apply').click();
    const req = search();
    expect(req.request.params.get('dnssec')).toBe('bogus');
    expect(req.request.params.get('source')).toBe('cache_stale');
    expect(req.request.params.get('domain')).toBe('evil');
    expect(req.request.params.has('from')).toBe(true);
    req.flush({ entries: [] });
    button('Reset').click();
    expect(search().request.params.has('dnssec')).toBe(false);
  });

  it('loads more by cursor without duplicates, and reports a failure', async () => {
    const { fixture, el, search, button } = setup();
    await fixture.whenStable();
    search().flush({ entries: [rec(3), rec(2)], next_cursor: 'c1' });
    await fixture.whenStable();
    button('Load more').click();
    const req = search();
    expect(req.request.params.get('cursor')).toBe('c1');
    req.flush({ entries: [rec(2), rec(1)], next_cursor: 'c2' });
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(3);
    button('Load more').click();
    search().flush('nope', { status: 500, statusText: 'x' });
    await fixture.whenStable();
    expect(el.querySelector('[role=alert]')).not.toBeNull();
    expect(el.querySelectorAll('tbody tr').length).toBe(3);
  });

  it('live_tail_appends, pauses, buffers and resumes', async () => {
    const { fixture, el, search, button } = setup();
    await fixture.whenStable();
    search().flush({ entries: [rec(1)] });
    await fixture.whenStable();
    button('Live tail').click();
    await fixture.whenStable();
    const es = FakeSource.all[0];
    es.onopen?.();
    es.emit('query', JSON.stringify(rec(2)));
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(2);
    expect(el.querySelector('tbody tr button')?.textContent).toContain('h2.example.');

    button('Pause').click();
    es.emit('query', JSON.stringify(rec(3)));
    es.emit('query', JSON.stringify(rec(4)));
    es.emit('lagged');
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(2);
    expect(el.textContent).toContain('2 new queries waiting');
    expect(el.textContent).toContain('fell behind 1 time');

    button('Resume').click();
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(4);

    button('Live tail').click();
    expect(es.closed).toBe(true);
  });

  it('caps the buffer and restarts the tail with new filters', async () => {
    const { fixture, el, search, button, select } = setup();
    await fixture.whenStable();
    search().flush({ entries: [] });
    await fixture.whenStable();
    button('Live tail').click();
    const es = FakeSource.all[0];
    for (let i = 1; i <= MAX_ROWS + 5; i++) es.emit('query', JSON.stringify(rec(i)));
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(MAX_ROWS);

    select('f-dnssec', 'secure');
    button('Apply').click();
    search().flush({ entries: [] });
    expect(es.closed).toBe(true);
    expect(FakeSource.all[1].url).toContain('dnssec=secure');
    es.onerror?.();
  });

  it('opens and closes the row drawer', async () => {
    const { fixture, el, search } = setup();
    await fixture.whenStable();
    search().flush({ entries: [rec(1)] });
    await fixture.whenStable();
    (el.querySelector('tbody button') as HTMLButtonElement).click();
    await fixture.whenStable();
    expect(el.querySelector('app-row-drawer')).not.toBeNull();
    (el.querySelector('app-row-drawer button') as HTMLButtonElement).click();
    await fixture.whenStable();
    expect(el.querySelector('app-row-drawer')).toBeNull();
  });

  it('disables the live tail for viewers', async () => {
    const { fixture, search, button } = setup('viewer');
    await fixture.whenStable();
    search().flush({ entries: [] });
    await fixture.whenStable();
    expect(button('Live tail').disabled).toBe(true);
  });
});
