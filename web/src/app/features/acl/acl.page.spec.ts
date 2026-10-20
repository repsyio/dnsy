import { mount, problem, type, clickByText } from '../admin-shared/testing';
import { AclPage } from './acl.page';

const OVERVIEW = {
  default_action: 'allow',
  rate_limit_qps: 20,
  rules: [{ id: 1, action: 'refuse', cidr: '10.0.0.0/8', comment: 'lan' }],
};

async function ready(overview: object = OVERVIEW) {
  const ctx = mount(AclPage);
  await ctx.fixture.whenStable();
  ctx.http.expectOne('/api/v1/acl').flush(overview);
  await ctx.fixture.whenStable();
  return ctx;
}

describe('AclPage', () => {
  it('shows rules, default action and rate limit', async () => {
    const { el } = await ready();
    expect(el.textContent).toContain('10.0.0.0/8');
    expect(el.textContent).toContain('allow');
    expect(el.querySelector<HTMLInputElement>('#rl-qps')!.value).toBe('20');
  });

  it('shows loading, empty and error states', async () => {
    const loading = mount(AclPage);
    await loading.fixture.whenStable();
    expect(loading.el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    loading.http.expectOne('/api/v1/acl').flush('x', { status: 500, statusText: 'x' });
    await loading.fixture.whenStable();
    expect(loading.el.querySelector('dnsy-mascot-error')).not.toBeNull();
  });

  it('shows the empty state', async () => {
    const { el } = await ready({ ...OVERVIEW, rules: [] });
    expect(el.querySelector('dnsy-mascot-empty')).not.toBeNull();
  });

  it('acl_cidr_validation: rejects a bad CIDR without calling the API', async () => {
    const { fixture, http, el } = await ready();
    type(el, '#acl-cidr', '10.0.0.0/33');
    clickByText(el, 'Add rule');
    await fixture.whenStable();
    http.expectNone('/api/v1/acl');
    expect(el.querySelector('#acl-cidr-err')?.textContent).toContain('Prefix length');
    expect(el.querySelector('#acl-cidr')!.getAttribute('aria-invalid')).toBe('true');
  });

  it('adds a rule, trimming input, and shows server errors', async () => {
    const { fixture, http, el } = await ready();
    type(el, '#acl-cidr', ' 192.0.2.0/24 ');
    type(el, '#acl-comment', 'lab');
    el.querySelector<HTMLSelectElement>('#acl-action')!.value = 'drop';
    el.querySelector('#acl-action')!.dispatchEvent(new Event('change'));
    clickByText(el, 'Add rule');
    const req = http.expectOne('/api/v1/acl');
    expect(req.request.body).toEqual({ cidr: '192.0.2.0/24', action: 'drop', comment: 'lab' });
    const p = problem(409, 'duplicate rule');
    req.flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('duplicate rule');
    clickByText(el, 'Add rule');
    http
      .expectOne('/api/v1/acl')
      .flush(
        { id: 2, action: 'drop', cidr: '192.0.2.0/24', comment: 'lab' },
        { status: 201, statusText: 'Created' },
      );
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(2);
  });

  it('removes a rule only after confirmation', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Remove');
    await fixture.whenStable();
    http.expectNone('/api/v1/acl/1');
    clickByText(el.querySelector('app-confirm-dialog')!, 'Remove');
    http.expectOne('/api/v1/acl/1').flush(null, { status: 204, statusText: 'No Content' });
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(0);
  });

  it('keeps the rule when removal fails', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Remove');
    await fixture.whenStable();
    clickByText(el.querySelector('app-confirm-dialog')!, 'Remove');
    const p = problem(404, 'no such rule');
    http.expectOne('/api/v1/acl/1').flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('no such rule');
    expect(el.querySelectorAll('tbody tr').length).toBe(1);
  });

  it('validates and saves the rate limit', async () => {
    const { fixture, http, el } = await ready();
    type(el, '#rl-qps', 'abc');
    clickByText(el, 'Save');
    await fixture.whenStable();
    http.expectNone('/api/v1/acl/rate-limit');
    expect(el.textContent).toContain('whole number');
    type(el, '#rl-qps', '50');
    clickByText(el, 'Save');
    const req = http.expectOne('/api/v1/acl/rate-limit');
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ qps: 50 });
    req.flush({ qps: 50 });
    await fixture.whenStable();
    expect(el.textContent).toContain('Rate limit saved');
  });

  it('shows a rate limit rejection', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Save');
    const p = problem(422, 'too high');
    http.expectOne('/api/v1/acl/rate-limit').flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('too high');
  });
});
