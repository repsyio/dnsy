import { mount, problem, type, clickByText } from '../admin-shared/testing';
import { SettingsPage, validateForm } from './settings.page';

const SETTINGS = {
  filter: { block_mode: 'null_ip' },
  querylog: { retention_days: 30 },
  limits: { per_client_qps: 0 },
  cache: {
    min_ttl: 60,
    max_ttl: 86400,
    serve_stale: { enabled: true },
    prefetch: { enabled: false },
  },
};

async function ready() {
  const ctx = mount(SettingsPage);
  await ctx.fixture.whenStable();
  ctx.http.expectOne('/api/v1/settings').flush(SETTINGS);
  await ctx.fixture.whenStable();
  return ctx;
}

describe('SettingsPage', () => {
  it('fills the form from the API', async () => {
    const { el } = await ready();
    expect(el.querySelector<HTMLInputElement>('#set-ret')!.value).toBe('30');
    expect(el.querySelector<HTMLInputElement>('#set-min')!.value).toBe('60');
    expect(el.querySelector<HTMLInputElement>('#set-stale')!.checked).toBe(true);
    expect(el.querySelector<HTMLInputElement>('#set-prefetch')!.checked).toBe(false);
    expect(el.querySelector<HTMLSelectElement>('#set-block')!.value).toBe('null_ip');
    expect(el.querySelector('input[type=password]')).toBeNull();
  });

  it('shows loading and error states with retry', async () => {
    const ctx = mount(SettingsPage);
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    ctx.http.expectOne('/api/v1/settings').flush('x', { status: 500, statusText: 'x' });
    await ctx.fixture.whenStable();
    clickByText(ctx.el, 'Retry');
    ctx.http.expectOne('/api/v1/settings').flush(SETTINGS);
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('form')).not.toBeNull();
  });

  it('validates numbers and the TTL clamp locally', async () => {
    const { fixture, http, el } = await ready();
    type(el, '#set-ret', 'many');
    type(el, '#set-min', '500');
    type(el, '#set-max', '100');
    clickByText(el, 'Save settings');
    await fixture.whenStable();
    http.expectNone('/api/v1/settings');
    expect(el.textContent).toContain('Query log retention must be a whole number');
    expect(el.textContent).toContain('Minimum TTL cannot exceed');
    expect(
      validateForm({
        blockMode: 'null_ip',
        perClientQps: '1',
        retentionDays: '1',
        minTtl: '1',
        maxTtl: '1',
        serveStale: false,
        prefetch: false,
      }),
    ).toEqual({});
  });

  it('saves the full patch and reflects the result', async () => {
    const { fixture, http, el } = await ready();
    type(el, '#set-qps', '25');
    el.querySelector<HTMLSelectElement>('#set-block')!.value = 'nxdomain';
    el.querySelector('#set-block')!.dispatchEvent(new Event('change'));
    const prefetch = el.querySelector<HTMLInputElement>('#set-prefetch')!;
    prefetch.checked = true;
    prefetch.dispatchEvent(new Event('change'));
    clickByText(el, 'Save settings');
    const req = http.expectOne('/api/v1/settings');
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual({
      filter: { block_mode: 'nxdomain' },
      limits: { per_client_qps: 25 },
      querylog: { retention_days: 30 },
      cache: {
        min_ttl: 60,
        max_ttl: 86400,
        serve_stale: { enabled: true },
        prefetch: { enabled: true },
      },
    });
    req.flush({ ...SETTINGS, limits: { per_client_qps: 25 } });
    await fixture.whenStable();
    expect(el.textContent).toContain('Settings saved');
  });

  it('surfaces server-side validation errors', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Save settings');
    const p = problem(422, 'cache.max_ttl must be at most 604800');
    http.expectOne('/api/v1/settings').flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.querySelector('p[role=alert]')?.textContent).toContain(
      'cache.max_ttl must be at most 604800',
    );
    expect(el.textContent).not.toContain('Settings saved');
  });
});
