import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { AuthService } from '../../core/auth.service';
import { clickByText, mount, problem, type } from '../admin-shared/testing';
import { ProfilePage } from './profile.page';

const ME = { id: 1, username: 'root', role: 'admin', created_at: 0, auth: 'session' };

function setup(auth: Record<string, unknown> = {}) {
  TestBed.overrideProvider(AuthService, {
    useValue: { user: signal(ME), logout: vi.fn().mockResolvedValue(undefined), ...auth },
  });
  return mount(ProfilePage);
}

async function fill(el: HTMLElement, cur: string, next: string, conf: string) {
  type(el, '#pp-cur', cur);
  type(el, '#pp-new', next);
  type(el, '#pp-conf', conf);
  await new Promise((r) => setTimeout(r));
}

describe('ProfilePage', () => {
  it('shows the account and session info', async () => {
    const { fixture, el } = setup();
    await fixture.whenStable();
    expect(el.textContent).toContain('root');
    expect(el.textContent).toContain('admin');
    expect(el.textContent).toContain('session');
    expect(el.textContent).toContain('30 minutes');
  });

  it('shows loading when the user is not known yet', async () => {
    const { fixture, el } = setup({ user: signal(null) });
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-loading')).not.toBeNull();
  });

  it('gives live strength hints', async () => {
    const { fixture, el } = setup();
    await fixture.whenStable();
    type(el, '#pp-new', 'abc');
    await fixture.whenStable();
    expect(el.querySelector('#pp-hints')!.textContent).toContain('Too weak');
    type(el, '#pp-new', 'Correct-Horse-9-Battery');
    await fixture.whenStable();
    expect(el.querySelector('#pp-hints')!.textContent).toContain('Strong');
  });

  it.each([
    ['', 'Longenough-1!', 'Longenough-1!', 'current password'],
    ['old', 'short', 'short', 'at least 8'],
    ['old', 'Longenough-1!', 'different-1!', 'do not match'],
  ])('rejects bad input locally (%s)', async (cur, next, conf, msg) => {
    const { fixture, el, http } = setup();
    await fixture.whenStable();
    await fill(el, cur, next, conf);
    clickByText(el, 'Change password');
    await fixture.whenStable();
    expect(el.textContent).toContain(msg);
    http.expectNone('/api/v1/auth/me/password');
  });

  it('changes the password and clears the fields', async () => {
    const { fixture, el, http } = setup();
    await fixture.whenStable();
    await fill(el, 'old', 'Longenough-1!', 'Longenough-1!');
    clickByText(el, 'Change password');
    const req = http.expectOne('/api/v1/auth/me/password');
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ current_password: 'old', new_password: 'Longenough-1!' });
    req.flush(ME);
    await fixture.whenStable();
    expect(el.textContent).toContain('Password changed');
    expect(el.querySelector<HTMLInputElement>('#pp-cur')!.value).toBe('');
  });

  it('keeps the user signed in on a wrong current password', async () => {
    const refresh = vi.fn().mockResolvedValue(ME);
    const { fixture, el, http } = setup({ refresh });
    await fixture.whenStable();
    await fill(el, 'bad', 'Longenough-1!', 'Longenough-1!');
    clickByText(el, 'Change password');
    const p = problem(401, 'current password is wrong');
    http.expectOne('/api/v1/auth/me/password').flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('current password is wrong');
  });

  it('goes to login when the 401 means the session is gone', async () => {
    const refresh = vi.fn().mockResolvedValue(null);
    const { fixture, el, http } = setup({ refresh });
    const nav = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    await fixture.whenStable();
    await fill(el, 'bad', 'Longenough-1!', 'Longenough-1!');
    clickByText(el, 'Change password');
    http.expectOne('/api/v1/auth/me/password').flush('x', { status: 401, statusText: 'x' });
    await vi.waitFor(() => expect(nav).toHaveBeenCalledWith(['/login']));
  });

  it('signs out', async () => {
    const logout = vi.fn().mockResolvedValue(undefined);
    const { fixture, el } = setup({ logout });
    const nav = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    await fixture.whenStable();
    clickByText(el, 'Sign out');
    await vi.waitFor(() => expect(nav).toHaveBeenCalledWith(['/login']));
    expect(logout).toHaveBeenCalled();
  });
});
