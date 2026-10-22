import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { DashboardPage, REFRESH_MS } from './dashboard.page';

const summary = (total: number, dropped = 0) => ({
  total,
  blocked: 10,
  blocked_ratio: 0.1,
  avg_latency_us: 12_340,
  max_latency_us: 90_000,
  by_rcode: {},
  by_source: {},
  cache_hit_ratio: 0.5,
  cache_hits: 50,
  cache_misses: 50,
  stale_answers: 2,
  dnssec: { secure: 8, bogus: 2 },
  querylog_dropped: dropped,
  querylog_flush_errors: 0,
  from: 0,
  to: 1,
});

describe('DashboardPage', () => {
  let ctrl: HttpTestingController;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    ctrl = TestBed.inject(HttpTestingController);
  });
  afterEach(() => vi.useRealTimers());

  function answer(
    opts: {
      total?: number;
      dropped?: number;
      cacheFails?: boolean;
      clockTrusted?: boolean;
      groups?: unknown;
    } = {},
  ) {
    const total = opts.total ?? 100;
    ctrl
      .expectOne((r) => r.url === '/api/v1/stats/dashboard')
      .flush({
        summary: summary(total, opts.dropped),
        series: [
          {
            start_ms: Date.now() - 120_000,
            total: 5,
            blocked: 1,
            cache_hits: 2,
            max_latency_us: 1,
          },
        ],
        top_domains: [{ key: 'a.example', count: 9 }],
        top_blocked: [{ key: 'ads.example', count: 4 }],
        top_clients: [],
      });
    const cache = ctrl.expectOne('/api/v1/cache');
    if (opts.cacheFails) cache.flush(null, { status: 503, statusText: 'Unavailable' });
    else cache.flush({ entries: 12, capacity: 1000 });
    ctrl
      .expectOne('/api/v1/dnssec/status')
      .flush({ clock_trusted: opts.clockTrusted ?? true, counters: {}, bogus: 2, secure: 8 });
    ctrl.expectOne('/api/v1/upstream-groups').flush(
      opts.groups ?? [
        {
          health: [
            { upstream: 'a', available: true, consecutive_failures: 0 },
            { upstream: 'b', available: false, consecutive_failures: 3 },
          ],
        },
        { health: null },
      ],
    );
  }

  async function mount() {
    const fixture = TestBed.createComponent(DashboardPage);
    await fixture.whenStable();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  const tile = (el: HTMLElement, id: string) =>
    el.querySelector(`[data-tile="${id}"]`)?.textContent?.replace(/\s+/g, ' ').trim();

  it('shows the loading mascot, then tiles, chart and top lists', async () => {
    const { fixture, el } = await mount();
    expect(el.querySelector('[data-testid="loading"]')).not.toBeNull();
    answer();
    await fixture.whenStable();
    expect(el.querySelector('[data-testid="loading"]')).toBeNull();
    expect(tile(el, 'queries')).toContain('100');
    expect(tile(el, 'blocked')).toContain('10.0%');
    expect(tile(el, 'cache-hit')).toContain('50.0%');
    expect(tile(el, 'cache-size')).toContain('12 / 1,000');
    expect(tile(el, 'latency')).toContain('12.3 ms');
    expect(tile(el, 'dnssec-secure')).toContain('80.0%');
    expect(tile(el, 'dnssec-bogus')).toContain('2');
    expect(tile(el, 'upstreams')).toContain('1 / 2');
    expect(el.querySelector('[data-testid="clock-banner"]')).toBeNull();
    expect(el.querySelector('svg[data-testid="chart"] title')?.textContent).toContain(
      'Queries over the last',
    );
    expect(el.textContent).toContain('a.example');
    expect(el.textContent).toContain('ads.example');
    expect(el.querySelector('[style]')).toBeNull();
  });

  it('one_refresh_issues_one_stats_request', async () => {
    const { fixture } = await mount();
    const stats = ctrl.match((r) => r.url.startsWith('/api/v1/stats/'));
    expect(stats.map((r) => r.request.url)).toEqual(['/api/v1/stats/dashboard']);
    expect(stats[0].request.params.get('limit')).toBe('10');
    stats[0].flush(null, { status: 500, statusText: 'Boom' });
    ctrl.match(() => true);
    await fixture.whenStable();
  });

  it('empty_range_shows_mascot', async () => {
    const { fixture, el } = await mount();
    answer({ total: 0 });
    await fixture.whenStable();
    expect(el.querySelector('[data-testid="empty"]')).not.toBeNull();
    expect(el.querySelector('[data-testid="chart"]')).toBeNull();
    expect(tile(el, 'blocked')).toContain('-');
  });

  it('degrades optional tiles and warns about an untrusted clock', async () => {
    const { fixture, el } = await mount();
    answer({ cacheFails: true, clockTrusted: false, groups: [] });
    await fixture.whenStable();
    expect(tile(el, 'cache-size')).toContain('cache unavailable');
    expect(el.querySelector('[data-testid="clock-banner"]')).not.toBeNull();
  });

  it('shows a badge when query-log events were dropped', async () => {
    const { fixture, el } = await mount();
    answer({ dropped: 1234 });
    await fixture.whenStable();
    expect(el.querySelector('[data-testid="dropped-badge"]')?.textContent).toContain('1,234');
  });

  it('hides the dropped badge when nothing was dropped', async () => {
    const { fixture, el } = await mount();
    answer();
    await fixture.whenStable();
    expect(el.querySelector('[data-testid="dropped-badge"]')).toBeNull();
  });

  it('shows the error mascot and retries', async () => {
    const { fixture, el } = await mount();
    ctrl
      .expectOne((r) => r.url === '/api/v1/stats/dashboard')
      .flush(null, { status: 500, statusText: 'Boom' });
    await fixture.whenStable();
    expect(el.querySelector('[data-testid="error"]')).not.toBeNull();
    ctrl.match(() => true); // requests cancelled by the failed forkJoin
    el.querySelector<HTMLButtonElement>('[data-testid="error"] button')!.click();
    await fixture.whenStable();
    answer();
    await fixture.whenStable();
    expect(el.querySelector('[data-testid="error"]')).toBeNull();
    expect(tile(el, 'queries')).toContain('100');
  });

  it('switches range and refetches with the 7d bucket', async () => {
    const { fixture, el } = await mount();
    answer();
    await fixture.whenStable();
    el.querySelector<HTMLButtonElement>('[data-range="7d"]')!.click();
    await fixture.whenStable();
    const ts = ctrl.expectOne((r) => r.url === '/api/v1/stats/dashboard');
    expect(ts.request.params.get('bucket')).toBe('7200');
    ctrl.match(() => true);
    el.querySelector<HTMLButtonElement>('[data-range="7d"]')!.click(); // no-op: already selected
    ctrl.expectNone(() => true);
  });

  it('auto-refreshes until paused', async () => {
    const { fixture, el } = await mount();
    answer();
    await fixture.whenStable();
    vi.advanceTimersByTime(REFRESH_MS);
    answer({ total: 200 });
    await fixture.whenStable();
    expect(tile(el, 'queries')).toContain('200');

    el.querySelector<HTMLButtonElement>('[data-testid="pause"]')!.click();
    await fixture.whenStable();
    expect(el.querySelector('[data-testid="pause"]')?.textContent).toContain('Resume');
    vi.advanceTimersByTime(REFRESH_MS * 2);
    ctrl.expectNone((r) => r.url === '/api/v1/stats/dashboard');
    el.querySelector<HTMLButtonElement>('[data-testid="pause"]')!.click();
    await fixture.whenStable();
    vi.advanceTimersByTime(REFRESH_MS);
    answer();
  });

  it('offers the chart as a table', async () => {
    const { fixture, el } = await mount();
    answer();
    await fixture.whenStable();
    el.querySelector<HTMLButtonElement>('[data-testid="toggle-table"]')!.click();
    await fixture.whenStable();
    expect(el.querySelector('[data-testid="chart"]')).toBeNull();
    const rows = el.querySelectorAll('[data-testid="chart-table"] tbody tr');
    expect(rows.length).toBeGreaterThan(10);
  });

  it('ignores a response for a range that is no longer selected', async () => {
    const { fixture, el } = await mount();
    el.querySelector<HTMLButtonElement>('[data-range="1h"]')!.click();
    await fixture.whenStable();
    const stale = ctrl.match((r) => r.url === '/api/v1/stats/dashboard');
    expect(stale).toHaveLength(2);
    ctrl.match(() => true);
    expect(el.querySelector('[data-testid="loading"]')).not.toBeNull();
  });

  it('does_not_stack_a_tick_on_a_running_load', async () => {
    await mount();
    // first load still pending: ticks must not issue a second batch
    vi.advanceTimersByTime(REFRESH_MS * 3);
    expect(ctrl.match((r) => r.url === '/api/v1/stats/dashboard')).toHaveLength(1);
    ctrl.match(() => true);
  });

  it('skips_polling_while_the_tab_is_hidden_and_refreshes_on_return', async () => {
    const { fixture } = await mount();
    answer();
    await fixture.whenStable();
    const hidden = vi.spyOn(document, 'hidden', 'get').mockReturnValue(true);
    vi.advanceTimersByTime(REFRESH_MS * 2);
    ctrl.expectNone((r) => r.url === '/api/v1/stats/dashboard');
    hidden.mockReturnValue(false);
    document.dispatchEvent(new Event('visibilitychange'));
    answer();
    hidden.mockRestore();
  });
});
