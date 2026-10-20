import { mount, problem, type, clickByText } from '../admin-shared/testing';
import { FilteringPage } from './filtering.page';

const LIST = {
  id: 1,
  name: 'ads',
  location: 'https://x/hosts',
  format: 'hosts',
  enabled: true,
  interval_secs: 3600,
  allow_private: false,
  entries: 42,
  last_fetched: 0,
  last_status: 'ok',
};
const RULE = { id: 7, kind: 'block', domain: 'bad.example' };

async function ready(lists: unknown[] = [LIST], rules: unknown[] = [RULE]) {
  const ctx = mount(FilteringPage);
  await ctx.fixture.whenStable();
  ctx.http.expectOne('/api/v1/blocklists').flush(lists);
  ctx.http.expectOne('/api/v1/rules').flush(rules);
  await ctx.fixture.whenStable();
  return ctx;
}

describe('FilteringPage', () => {
  it('shows loading, then sources and rules', async () => {
    const ctx = mount(FilteringPage);
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    ctx.http.expectOne('/api/v1/blocklists').flush([LIST]);
    ctx.http.expectOne('/api/v1/rules').flush([RULE]);
    await ctx.fixture.whenStable();
    expect(ctx.el.textContent).toContain('ads');
    expect(ctx.el.textContent).toContain('42');
    expect(ctx.el.textContent).toContain('bad.example');
  });

  it('shows empty states', async () => {
    const { el } = await ready([], []);
    expect(el.querySelectorAll('dnsy-mascot-empty').length).toBe(2);
  });

  it('shows an error and retries', async () => {
    const ctx = mount(FilteringPage);
    await ctx.fixture.whenStable();
    ctx.http.expectOne('/api/v1/blocklists').flush('x', { status: 500, statusText: 'x' });
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-error')).not.toBeNull();
    clickByText(ctx.el, 'Retry');
    await ctx.fixture.whenStable();
    ctx.http.expectOne('/api/v1/blocklists').flush([]);
    ctx.http
      .match('/api/v1/rules')
      .filter((r) => !r.cancelled)
      .forEach((r) => r.flush([]));
  });

  it('adds a source and surfaces a server rejection', async () => {
    const { fixture, http, el } = await ready([], []);
    clickByText(el, 'Add source');
    await fixture.whenStable();
    expect(el.textContent).toContain('Name and location are required');
    type(el, '#bl-name', 'ads');
    type(el, '#bl-loc', 'https://x/hosts');
    clickByText(el, 'Add source');
    const req = http.expectOne('/api/v1/blocklists');
    expect(req.request.body).toEqual({ name: 'ads', location: 'https://x/hosts', format: 'auto' });
    const p = problem(422, 'unsupported location');
    req.flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('unsupported location');
    clickByText(el, 'Add source');
    http.expectOne('/api/v1/blocklists').flush(LIST, { status: 201, statusText: 'Created' });
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(1);
  });

  it('toggles and refreshes a source', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Disable');
    const patch = http.expectOne('/api/v1/blocklists/1');
    expect(patch.request.body).toEqual({ enabled: false });
    patch.flush({ ...LIST, enabled: false });
    await fixture.whenStable();
    expect(el.textContent).toContain('disabled');
    clickByText(el, 'Refresh');
    http.expectOne('/api/v1/blocklists/1/refresh').flush({ outcome: 'updated', entries: 50 });
    http.expectOne('/api/v1/blocklists').flush([{ ...LIST, entries: 50 }]);
    await fixture.whenStable();
    expect(el.textContent).toContain('updated (50 entries)');
  });

  it('shows refresh failures', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Refresh');
    const p = problem(503, 'fetch failed');
    http.expectOne('/api/v1/blocklists/1/refresh').flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('fetch failed');
  });

  it('requires confirmation before removing a source', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Remove');
    await fixture.whenStable();
    http.expectNone('/api/v1/blocklists/1');
    clickByText(el.querySelector('app-confirm-dialog')!, 'Cancel');
    await fixture.whenStable();
    expect(el.querySelector('app-confirm-dialog')).toBeNull();
    clickByText(el, 'Remove');
    await fixture.whenStable();
    clickByText(el.querySelector('app-confirm-dialog')!, 'Remove');
    http.expectOne('/api/v1/blocklists/1').flush(null, { status: 204, statusText: 'No Content' });
    await fixture.whenStable();
    expect(el.textContent).toContain('No blocklist sources yet');
  });

  it('adds and removes rules with confirmation', async () => {
    const { fixture, http, el } = await ready([], []);
    clickByText(el, 'Add rule');
    await fixture.whenStable();
    expect(el.textContent).toContain('Enter a domain');
    type(el, '#rule-domain', 'ads.example');
    el.querySelector<HTMLSelectElement>('#rule-kind')!.value = 'allow';
    el.querySelector('#rule-kind')!.dispatchEvent(new Event('change'));
    clickByText(el, 'Add rule');
    const req = http.expectOne('/api/v1/rules');
    expect(req.request.body).toEqual({ kind: 'allow', domain: 'ads.example' });
    req.flush(
      { id: 9, kind: 'allow', domain: 'ads.example' },
      { status: 201, statusText: 'Created' },
    );
    await fixture.whenStable();
    clickByText(el, 'Remove');
    await fixture.whenStable();
    clickByText(el.querySelector('app-confirm-dialog')!, 'Remove');
    const del = http.expectOne('/api/v1/rules/9');
    const p = problem(404, 'gone');
    del.flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('gone');
  });
});
