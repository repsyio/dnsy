import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthService } from '../../core/auth.service';
import { click, clickByText, mount, problem, type } from '../admin-shared/testing';
import { scopesForRole } from './tokens.service';
import { TokensPage } from './tokens.page';

const TOKENS = [
  {
    id: 1,
    user_id: 1,
    name: 'ci',
    scopes: ['api:read'],
    created_at: 0,
    expires_at: null,
    last_used_at: 60,
    revoked: false,
  },
  {
    id: 2,
    user_id: 1,
    name: 'old',
    scopes: ['dns:query'],
    created_at: 0,
    expires_at: 100,
    last_used_at: null,
    revoked: true,
  },
];
const SECRET = 'dnsy_ABC_supersecretvalue';

async function ready(role = 'operator', tokens: unknown[] = TOKENS) {
  TestBed.overrideProvider(AuthService, { useValue: { user: signal({ id: 1, role }) } });
  const ctx = mount(TokensPage);
  await ctx.fixture.whenStable();
  ctx.http.expectOne('/api/v1/tokens').flush(tokens);
  await ctx.fixture.whenStable();
  return ctx;
}

async function createToken(ctx: Awaited<ReturnType<typeof ready>>, scope = 'dns:query') {
  const { el, http, fixture } = ctx;
  type(el, '#tc-name', 'laptop');
  click(el, `#tc-s-${CSS.escape(scope)}`);
  clickByText(el, 'Create token');
  const req = http.expectOne((r) => r.method === 'POST' && r.url === '/api/v1/tokens');
  req.flush({ token: SECRET, meta: { ...TOKENS[0], id: 3, name: 'laptop', scopes: [scope] } });
  await fixture.whenStable();
  http.expectOne('/api/v1/tokens').flush(TOKENS);
  await fixture.whenStable();
}

describe('TokensPage', () => {
  it('limits the scope picker to the role', async () => {
    expect(scopesForRole('viewer')).toEqual(['api:read']);
    expect(scopesForRole('admin')).toContain('admin');
    const { el } = await ready('operator');
    expect(el.querySelector('#tc-s-api\\:write')).not.toBeNull();
    expect(el.querySelector('#tc-s-admin')).toBeNull();
    expect(el.textContent).toContain('/dns-query/<token>');
  });

  it('lists tokens with last used, expiry and status; revoked ones have no revoke button', async () => {
    const { el } = await ready();
    expect(el.textContent).toContain('1970-01-01 00:01 UTC');
    expect(el.textContent).toContain('never');
    expect(el.textContent).toContain('revoked');
    expect(el.querySelector('[aria-label="Revoke token ci"]')).not.toBeNull();
    expect(el.querySelector('[aria-label="Revoke token old"]')).toBeNull();
  });

  it('shows loading, error and empty states', async () => {
    TestBed.overrideProvider(AuthService, { useValue: { user: signal({ id: 1, role: 'admin' }) } });
    const ctx = mount(TokensPage);
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    ctx.http.expectOne('/api/v1/tokens').flush('x', { status: 500, statusText: 'x' });
    await ctx.fixture.whenStable();
    clickByText(ctx.el, 'Retry');
    ctx.http.expectOne('/api/v1/tokens').flush([]);
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-empty')).not.toBeNull();
  });

  it('validates name, scopes and expiry before calling the API', async () => {
    const { el, http, fixture } = await ready();
    clickByText(el, 'Create token');
    await fixture.whenStable();
    expect(el.textContent).toContain('Enter a name');
    type(el, '#tc-name', 'x');
    clickByText(el, 'Create token');
    await fixture.whenStable();
    expect(el.textContent).toContain('at least one scope');
    click(el, '#tc-s-api\\:read');
    type(el, '#tc-exp', '2000-01-01');
    clickByText(el, 'Create token');
    await fixture.whenStable();
    expect(el.textContent).toContain('in the future');
    http.expectNone('/api/v1/tokens');
  });

  it('sends the expiry as unix seconds and shows API errors', async () => {
    const { el, http, fixture } = await ready();
    type(el, '#tc-name', 'x');
    click(el, '#tc-s-api\\:read');
    type(el, '#tc-exp', '2099-01-01');
    clickByText(el, 'Create token');
    const req = http.expectOne((r) => r.method === 'POST');
    expect(req.request.body.expires_at).toBe(Date.parse('2099-01-01T23:59:59Z') / 1000);
    const p = problem(403, 'tokens need a session');
    req.flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('tokens need a session');
  });

  it('token_secret_hidden_after_close', async () => {
    const ctx = await ready();
    await createToken(ctx);
    const { el, fixture } = ctx;
    const input = el.querySelector<HTMLInputElement>('#tk-secret')!;
    expect(input.value).toBe(SECRET);
    expect(el.textContent).toContain('shown only once');
    expect(el.querySelector('[role="alert"]')).not.toBeNull();
    clickByText(el, 'I have saved it');
    await fixture.whenStable();
    expect(el.querySelector('#tk-secret')).toBeNull();
    expect(el.innerHTML).not.toContain(SECRET);
    expect(JSON.stringify({ ...localStorage })).not.toContain(SECRET);
    expect(JSON.stringify({ ...sessionStorage })).not.toContain(SECRET);
  });

  it('closing the secret dialog with Escape also drops the secret', async () => {
    const ctx = await ready();
    await createToken(ctx);
    ctx.el
      .querySelector('[role="dialog"]')!
      .dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    await ctx.fixture.whenStable();
    expect(ctx.el.innerHTML).not.toContain(SECRET);
  });

  it('copies the secret and the DoH URL, and reports a refused clipboard', async () => {
    const write = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: write },
      configurable: true,
    });
    const ctx = await ready();
    await createToken(ctx);
    clickByText(ctx.el, 'Copy secret');
    await ctx.fixture.whenStable();
    expect(write).toHaveBeenCalledWith(SECRET);
    clickByText(ctx.el, 'Copy DoH URL');
    await ctx.fixture.whenStable();
    expect(write).toHaveBeenCalledWith(`https://${location.host}/dns-query/${SECRET}`);
    expect(ctx.el.textContent).toContain('DoH URL copied.');
    write.mockRejectedValue(new Error('denied'));
    clickByText(ctx.el, 'Copy secret');
    await vi.waitFor(() => expect(ctx.el.textContent).toContain('Copy failed'));
  });

  it('copies the DoH URL template', async () => {
    const write = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: write },
      configurable: true,
    });
    const { el, fixture } = await ready();
    clickByText(el, 'Copy URL');
    await fixture.whenStable();
    expect(write).toHaveBeenCalledWith(`https://${location.host}/dns-query/<token>`);
    expect(el.textContent).toContain('URL copied.');
  });

  it('does not offer the DoH URL for tokens without dns:query', async () => {
    const ctx = await ready();
    await createToken(ctx, 'api:read');
    expect(ctx.el.textContent).not.toContain('Copy DoH URL');
  });

  it('revokes after confirmation', async () => {
    const { el, http, fixture } = await ready();
    click(el, '[aria-label="Revoke token ci"]');
    await fixture.whenStable();
    const p = problem(500, 'boom');
    clickByText(el.querySelector<HTMLElement>('[role="dialog"]')!, 'Revoke');
    http.expectOne('/api/v1/tokens/1').flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('boom');
    clickByText(el.querySelector<HTMLElement>('[role="dialog"]')!, 'Revoke');
    http.expectOne('/api/v1/tokens/1').flush(null, { status: 204, statusText: 'No Content' });
    await fixture.whenStable();
    http.expectOne('/api/v1/tokens').flush(TOKENS);
    await fixture.whenStable();
    expect(el.textContent).toContain('Revoked ci.');
  });
});
