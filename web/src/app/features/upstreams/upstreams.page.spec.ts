import { mount, problem, type, clickByText } from '../../../testing/testing';
import { UpstreamsPage } from './upstreams.page';

const GROUP = {
  name: 'main',
  strategy: 'failover',
  default: true,
  domains: ['corp.example'],
  members: [
    { index: 0, upstream: '1.1.1.1:53', weight: 1 },
    { index: 1, upstream: '9.9.9.9:53', weight: 2 },
  ],
};
const HEALTH = [
  { upstream: '1.1.1.1:53', available: true, consecutive_failures: 0, latency_ms: 12 },
  { upstream: '9.9.9.9:53', available: false, consecutive_failures: 3 },
];

async function ready(groups: unknown[] = [GROUP], health: object | null = HEALTH) {
  const ctx = mount(UpstreamsPage);
  await ctx.fixture.whenStable();
  ctx.http.expectOne('/api/v1/upstream-groups').flush(groups);
  for (const g of groups as { name: string }[]) {
    const req = ctx.http.expectOne(`/api/v1/upstream-groups/${g.name}/health`);
    if (health === null) req.flush('x', { status: 503, statusText: 'x' });
    else req.flush(health);
  }
  await ctx.fixture.whenStable();
  return ctx;
}

describe('UpstreamsPage', () => {
  it('shows groups, members and health indicators', async () => {
    const { el } = await ready();
    expect(el.textContent).toContain('main');
    expect(el.textContent).toContain('default');
    expect(el.textContent).toContain('corp.example');
    expect(el.textContent).toContain('up');
    expect(el.textContent).toContain('12 ms');
    expect(el.textContent).toContain('down');
    expect(el.textContent).toContain('3 failures');
  });

  it('marks health unknown when the endpoint is unavailable', async () => {
    const { el } = await ready([GROUP], null);
    expect(el.textContent).toContain('unknown');
  });

  it('shows loading, error and empty states', async () => {
    const a = mount(UpstreamsPage);
    await a.fixture.whenStable();
    expect(a.el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    a.http.expectOne('/api/v1/upstream-groups').flush('x', { status: 500, statusText: 'x' });
    await a.fixture.whenStable();
    expect(a.el.querySelector('dnsy-mascot-error')).not.toBeNull();
  });

  it('shows the empty state', async () => {
    const b = await ready([]);
    expect(b.el.textContent).toContain('No upstream groups');
  });

  it('validates and creates a group', async () => {
    const { fixture, http, el } = await ready([]);
    type(el, '#grp-name', 'bad name!');
    clickByText(el, 'Create');
    await fixture.whenStable();
    expect(el.textContent).toContain('1 to 64 characters');
    type(el, '#grp-name', 'extra');
    clickByText(el, 'Create');
    await fixture.whenStable();
    expect(el.textContent).toContain('at least one upstream');
    type(el, '#grp-first', '8.8.8.8:53');
    clickByText(el, 'Create');
    const req = http.expectOne('/api/v1/upstream-groups');
    expect(req.request.body).toEqual({
      name: 'extra',
      strategy: 'round_robin',
      members: [{ upstream: '8.8.8.8:53' }],
    });
    const p = problem(409, 'group exists');
    req.flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('group exists');
    clickByText(el, 'Create');
    http
      .expectOne('/api/v1/upstream-groups')
      .flush(
        { ...GROUP, name: 'extra', default: false, domains: [] },
        { status: 201, statusText: 'Created' },
      );
    http.expectOne('/api/v1/upstream-groups/extra/health').flush([]);
    await fixture.whenStable();
    expect(el.querySelector('#g-extra')).not.toBeNull();
  });

  it('changes the strategy keeping members, weights and domains', async () => {
    const { fixture, http, el } = await ready();
    const sel = el.querySelector<HTMLSelectElement>('#st-main')!;
    sel.value = 'weighted';
    sel.dispatchEvent(new Event('change'));
    const req = http.expectOne('/api/v1/upstream-groups/main');
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({
      strategy: 'weighted',
      default: true,
      domains: ['corp.example'],
      members: [
        { upstream: '1.1.1.1:53', weight: 1 },
        { upstream: '9.9.9.9:53', weight: 2 },
      ],
    });
    req.flush({ ...GROUP, strategy: 'weighted' });
    http.expectOne('/api/v1/upstream-groups/main/health').flush(HEALTH);
    await fixture.whenStable();
    expect(el.querySelector<HTMLSelectElement>('#st-main')!.value).toBe('weighted');
  });

  it('ignores an unchanged strategy and surfaces a rejected change', async () => {
    const { fixture, http, el } = await ready();
    const sel = el.querySelector<HTMLSelectElement>('#st-main')!;
    sel.dispatchEvent(new Event('change'));
    http.expectNone('/api/v1/upstream-groups/main');
    sel.value = 'weighted';
    sel.dispatchEvent(new Event('change'));
    const p = problem(422, 'weights required');
    http.expectOne('/api/v1/upstream-groups/main').flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('weights required');
  });

  it('adds a member and shows errors', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Add member');
    await fixture.whenStable();
    expect(el.textContent).toContain('Enter an upstream address');
    type(el, '#am-main', 'tls://dns.example');
    clickByText(el, 'Add member');
    const p = problem(422, 'unreachable scheme');
    const req = http.expectOne('/api/v1/upstream-groups/main/upstreams');
    expect(req.request.body).toEqual({ upstream: 'tls://dns.example' });
    req.flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('unreachable scheme');
    clickByText(el, 'Add member');
    http.expectOne('/api/v1/upstream-groups/main/upstreams').flush(
      {
        ...GROUP,
        members: [...GROUP.members, { index: 2, upstream: 'tls://dns.example', weight: 1 }],
      },
      { status: 201, statusText: 'Created' },
    );
    http.expectOne('/api/v1/upstream-groups/main/health').flush(HEALTH);
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(3);
  });

  it('removes a member and a group only after confirmation', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Remove');
    await fixture.whenStable();
    http.expectNone('/api/v1/upstream-groups/main/upstreams/0');
    clickByText(el.querySelector('app-confirm-dialog')!, 'Remove');
    http
      .expectOne('/api/v1/upstream-groups/main/upstreams/0')
      .flush({ ...GROUP, members: [GROUP.members[1]] });
    http.expectOne('/api/v1/upstream-groups/main/health').flush(HEALTH);
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(1);

    clickByText(el, 'Delete group');
    await fixture.whenStable();
    clickByText(el.querySelector('app-confirm-dialog')!, 'Cancel');
    await fixture.whenStable();
    http.expectNone('/api/v1/upstream-groups/main');
    clickByText(el, 'Delete group');
    await fixture.whenStable();
    clickByText(el.querySelector('app-confirm-dialog')!, 'Delete');
    http
      .expectOne('/api/v1/upstream-groups/main')
      .flush(null, { status: 204, statusText: 'No Content' });
    await fixture.whenStable();
    expect(el.textContent).toContain('No upstream groups');
  });

  it('shows why deleting a group failed', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Delete group');
    await fixture.whenStable();
    clickByText(el.querySelector('app-confirm-dialog')!, 'Delete');
    const p = problem(422, 'cannot delete the default group');
    http.expectOne('/api/v1/upstream-groups/main').flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('cannot delete the default group');
    expect(el.querySelector('#g-main')).not.toBeNull();
  });
});
