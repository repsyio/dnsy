import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthService } from '../../core/auth.service';
import { click, clickByText, mount, problem, type } from '../admin-shared/testing';
import { UsersPage } from './users.page';

const USERS = [
  { id: 1, username: 'root', role: 'admin', created_at: 0 },
  { id: 2, username: 'ann', role: 'viewer', created_at: 86400 },
];

const dlg = (el: HTMLElement) => el.querySelector<HTMLElement>('[role="dialog"]')!;

async function ready(users: unknown[] = USERS) {
  TestBed.overrideProvider(AuthService, {
    useValue: { user: signal({ id: 1, username: 'root', role: 'admin' }) },
  });
  const ctx = mount(UsersPage);
  await ctx.fixture.whenStable();
  ctx.http.expectOne('/api/v1/users').flush(users);
  await ctx.fixture.whenStable();
  return ctx;
}

describe('UsersPage', () => {
  it('lists users, marks the current one and blocks self-delete', async () => {
    const { el } = await ready();
    expect(el.textContent).toContain('ann');
    expect(el.textContent).toContain('(you)');
    expect(el.querySelector<HTMLButtonElement>('[aria-label="Delete root"]')!.disabled).toBe(true);
    expect(el.querySelector<HTMLButtonElement>('[aria-label="Delete ann"]')!.disabled).toBe(false);
  });

  it('shows loading, error with retry, and empty states', async () => {
    const ctx = mount(UsersPage);
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    ctx.http.expectOne('/api/v1/users').flush('x', { status: 500, statusText: 'x' });
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-error')).not.toBeNull();
    clickByText(ctx.el, 'Retry');
    ctx.http.expectOne('/api/v1/users').flush([]);
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-empty')).not.toBeNull();
  });

  it('creates a user after validating locally', async () => {
    const ctx = await ready();
    const { el, http, fixture } = ctx;
    clickByText(el, 'Create user');
    await fixture.whenStable();
    clickByText(dlg(el), 'Create');
    await fixture.whenStable();
    expect(el.textContent).toContain('Enter a username.');
    type(el, '#ud-name', 'bob');
    type(el, '#ud-pw', 'short');
    clickByText(dlg(el), 'Create');
    await fixture.whenStable();
    expect(el.textContent).toContain('at least 8');
    type(el, '#ud-pw', 'Longenough-1!');
    el.querySelector<HTMLSelectElement>('#ud-role')!.value = 'operator';
    el.querySelector('#ud-role')!.dispatchEvent(new Event('change'));
    clickByText(dlg(el), 'Create');
    const req = http.expectOne('/api/v1/users');
    expect(req.request.body).toEqual({
      username: 'bob',
      password: 'Longenough-1!',
      role: 'operator',
    });
    req.flush({ id: 3, username: 'bob', role: 'operator', created_at: 1 });
    await fixture.whenStable();
    http.expectOne('/api/v1/users').flush(USERS);
    await fixture.whenStable();
    expect(el.textContent).toContain('User created.');
    expect(el.querySelector('[role="dialog"]')).toBeNull();
  });

  it('shows the server error when create fails', async () => {
    const { el, http, fixture } = await ready();
    clickByText(el, 'Create user');
    await fixture.whenStable();
    type(el, '#ud-name', 'ann');
    type(el, '#ud-pw', 'Longenough-1!');
    clickByText(dlg(el), 'Create');
    const p = problem(409, 'username taken');
    http.expectOne('/api/v1/users').flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('username taken');
  });

  it('changes a role', async () => {
    const { el, http, fixture } = await ready();
    click(el, '[aria-label="Change role of ann"]');
    await fixture.whenStable();
    el.querySelector<HTMLSelectElement>('#ud-role')!.value = 'operator';
    el.querySelector('#ud-role')!.dispatchEvent(new Event('change'));
    clickByText(el, 'Save role');
    const req = http.expectOne('/api/v1/users/2');
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual({ role: 'operator' });
    req.flush(USERS[1]);
    await fixture.whenStable();
    http.expectOne('/api/v1/users').flush(USERS);
  });

  it('resets a password', async () => {
    const { el, http, fixture } = await ready();
    click(el, '[aria-label="Reset password of ann"]');
    await fixture.whenStable();
    type(el, '#ud-pw', 'Longenough-1!');
    clickByText(el, 'Reset password');
    const req = http.expectOne('/api/v1/users/2');
    expect(req.request.body).toEqual({ password: 'Longenough-1!' });
    req.flush(USERS[1]);
    await fixture.whenStable();
    http.expectOne('/api/v1/users').flush(USERS);
  });

  it('deletes only after confirmation and reports failures', async () => {
    const { el, http, fixture } = await ready();
    click(el, '[aria-label="Delete ann"]');
    await fixture.whenStable();
    clickByText(dlg(el), 'Cancel');
    await fixture.whenStable();
    http.expectNone('/api/v1/users/2');
    click(el, '[aria-label="Delete ann"]');
    await fixture.whenStable();
    clickByText(dlg(el), 'Delete');
    const p = problem(409, 'cannot delete the last admin');
    http.expectOne('/api/v1/users/2').flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('cannot delete the last admin');
    clickByText(dlg(el), 'Delete');
    http.expectOne('/api/v1/users/2').flush(null, { status: 204, statusText: 'No Content' });
    await fixture.whenStable();
    http.expectOne('/api/v1/users').flush([USERS[0]]);
    await fixture.whenStable();
    expect(el.textContent).toContain('Deleted ann.');
  });
});
