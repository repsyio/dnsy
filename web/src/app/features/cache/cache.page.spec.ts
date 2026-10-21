import { TestBed } from '@angular/core/testing';
import { mount, problem, type, clickByText } from '../../../testing/testing';
import { CachePage, REFRESH_MS } from './cache.page';

const STATS = {
  entries: 10,
  capacity: 100,
  hits: 90,
  misses: 10,
  hit_ratio: 0.9,
  inserts: 12,
  evictions: 1,
  expired: 2,
  stale_served: 3,
  prefetches: 4,
};

async function ready() {
  const ctx = mount(CachePage);
  await ctx.fixture.whenStable();
  ctx.http.expectOne('/api/v1/cache').flush(STATS);
  await ctx.fixture.whenStable();
  return ctx;
}

afterEach(() => vi.useRealTimers());

describe('CachePage', () => {
  it('shows loading then the statistics', async () => {
    const ctx = mount(CachePage);
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    ctx.http.expectOne('/api/v1/cache').flush(STATS);
    await ctx.fixture.whenStable();
    expect(ctx.el.textContent).toContain('10 / 100');
    expect(ctx.el.textContent).toContain('90.0%');
    expect(ctx.el.textContent).toContain('Stale served');
  });

  it('shows an error and retries', async () => {
    const ctx = mount(CachePage);
    await ctx.fixture.whenStable();
    ctx.http.expectOne('/api/v1/cache').flush('x', { status: 503, statusText: 'x' });
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-error')).not.toBeNull();
    clickByText(ctx.el, 'Retry');
    ctx.http.expectOne('/api/v1/cache').flush(STATS);
    await ctx.fixture.whenStable();
    expect(ctx.el.textContent).toContain('Hit ratio');
  });

  it('polls for live stats, keeps old values on failure and stops on destroy', async () => {
    vi.useFakeTimers();
    const ctx = mount(CachePage);
    ctx.http.expectOne('/api/v1/cache').flush(STATS);
    await vi.advanceTimersByTimeAsync(REFRESH_MS);
    ctx.http.expectOne('/api/v1/cache').flush({ ...STATS, entries: 11 });
    await vi.advanceTimersByTimeAsync(0);
    ctx.fixture.detectChanges();
    expect(ctx.el.textContent).toContain('11 / 100');
    await vi.advanceTimersByTimeAsync(REFRESH_MS);
    ctx.http.expectOne('/api/v1/cache').flush('x', { status: 500, statusText: 'x' });
    ctx.fixture.detectChanges();
    expect(ctx.el.textContent).toContain('showing the last values');
    expect(ctx.el.textContent).toContain('11 / 100');
    ctx.fixture.destroy();
    await vi.advanceTimersByTimeAsync(REFRESH_MS * 2);
    ctx.http.expectNone('/api/v1/cache');
    TestBed.resetTestingModule();
  });

  it('cache_flush_requires_confirmation: flush-all waits for the dialog', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Flush entire cache');
    await fixture.whenStable();
    expect(el.querySelector('app-confirm-dialog')).not.toBeNull();
    http.expectNone({ method: 'DELETE', url: '/api/v1/cache' });
    clickByText(el.querySelector('app-confirm-dialog')!, 'Cancel');
    await fixture.whenStable();
    expect(el.querySelector('app-confirm-dialog')).toBeNull();
    http.expectNone({ method: 'DELETE', url: '/api/v1/cache' });

    clickByText(el, 'Flush entire cache');
    await fixture.whenStable();
    clickByText(el.querySelector('app-confirm-dialog')!, 'Flush cache');
    http.expectOne({ method: 'DELETE', url: '/api/v1/cache' }).flush({ removed: 10 });
    http.expectOne('/api/v1/cache').flush({ ...STATS, entries: 0 });
    await fixture.whenStable();
    expect(el.textContent).toContain('Flushed 10 entries (whole cache)');
    expect(el.querySelector('app-confirm-dialog')).toBeNull();
  });

  it('reports a failed flush-all', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Flush entire cache');
    await fixture.whenStable();
    clickByText(el.querySelector('app-confirm-dialog')!, 'Flush cache');
    const p = problem(503, 'resolver offline');
    http.expectOne({ method: 'DELETE', url: '/api/v1/cache' }).flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('resolver offline');
    expect(el.querySelector('app-confirm-dialog')).toBeNull();
  });

  it('flushes one name with or without its subtree', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Flush name');
    await fixture.whenStable();
    expect(el.textContent).toContain('Enter the domain name');
    type(el, '#fl-name', ' example.com ');
    clickByText(el, 'Flush name');
    let req = http.expectOne((r) => r.url === '/api/v1/cache/entries');
    expect(req.request.params.get('name')).toBe('example.com');
    expect(req.request.params.get('subtree')).toBe('false');
    req.flush({ removed: 1 });
    http.expectOne('/api/v1/cache').flush(STATS);
    await fixture.whenStable();
    expect(el.textContent).toContain('Flushed 1 entry (example.com)');

    const sub = el.querySelector<HTMLInputElement>('#fl-sub')!;
    sub.checked = true;
    sub.dispatchEvent(new Event('change'));
    clickByText(el, 'Flush name');
    req = http.expectOne((r) => r.url === '/api/v1/cache/entries');
    expect(req.request.params.get('subtree')).toBe('true');
    const p = problem(400, 'invalid name');
    req.flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('invalid name');
  });
});
