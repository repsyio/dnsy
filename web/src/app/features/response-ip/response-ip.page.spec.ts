import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthService } from '../../core/auth.service';
import { mount, problem, type, clickByText } from '../../../testing/testing';
import { ResponseIpPage } from './response-ip.page';

async function ready(cidrs: string[] = ['10.0.0.0/8'], role = 'operator') {
  TestBed.overrideProvider(AuthService, { useValue: { user: signal({ id: 1, role }) } });
  const ctx = mount(ResponseIpPage);
  await ctx.fixture.whenStable();
  ctx.http.expectOne('/api/v1/response-ip').flush({ cidrs });
  await ctx.fixture.whenStable();
  return ctx;
}

const area = (el: HTMLElement) => el.querySelector<HTMLTextAreaElement>('#rip-list')!;

describe('ResponseIpPage', () => {
  it('shows the list in the editor', async () => {
    const { el } = await ready(['10.0.0.0/8', 'fc00::/7']);
    expect(area(el).value).toBe('10.0.0.0/8\nfc00::/7');
  });

  it('shows loading and error states', async () => {
    TestBed.overrideProvider(AuthService, { useValue: { user: signal({ id: 1, role: 'admin' }) } });
    const { fixture, http, el } = mount(ResponseIpPage);
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    http.expectOne('/api/v1/response-ip').flush('x', { status: 500, statusText: 'x' });
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-error')).not.toBeNull();
  });

  it('shows the mascot empty state for an empty list', async () => {
    const { el } = await ready([]);
    expect(el.querySelector('dnsy-mascot-empty')).not.toBeNull();
  });

  it('response_ip_validation: rejects a bad entry without calling the API', async () => {
    const { fixture, http, el } = await ready();
    type(el, '#rip-list', '10.0.0.0/8\n10.0.0.0/33');
    clickByText(el, 'Save');
    await fixture.whenStable();
    http.expectNone('/api/v1/response-ip');
    expect(el.querySelector('#rip-err')?.textContent).toContain('10.0.0.0/33');
    expect(area(el).getAttribute('aria-invalid')).toBe('true');
  });

  it('replaces the whole list, splitting on lines and commas', async () => {
    const { fixture, http, el } = await ready();
    type(el, '#rip-list', '192.0.2.0/24, 2001:db8::1\n\n10.1.1.1 ');
    clickByText(el, 'Save');
    const req = http.expectOne('/api/v1/response-ip');
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ cidrs: ['192.0.2.0/24', '2001:db8::1', '10.1.1.1'] });
    req.flush({ cidrs: ['192.0.2.0/24', '2001:db8::1', '10.1.1.1'] });
    await fixture.whenStable();
    expect(el.textContent).toContain('Response IP policy saved.');
  });

  it('an empty text saves an empty list', async () => {
    const { fixture, http, el } = await ready();
    type(el, '#rip-list', '');
    clickByText(el, 'Save');
    const req = http.expectOne('/api/v1/response-ip');
    expect(req.request.body).toEqual({ cidrs: [] });
    req.flush({ cidrs: [] });
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-empty')).not.toBeNull();
  });

  it('shows the server 422 message', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Save');
    const p = problem(422, 'too many entries');
    http.expectOne('/api/v1/response-ip').flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.querySelector('#rip-err')?.textContent).toContain('too many entries');
  });

  it('a viewer sees the list read-only', async () => {
    const { el } = await ready(['10.0.0.0/8'], 'viewer');
    expect(el.querySelector('textarea')).toBeNull();
    expect(el.querySelector('button')).toBeNull();
    expect(el.textContent).toContain('10.0.0.0/8');
    expect(el.textContent).toContain('not change it');
  });

  it('a viewer sees the empty state for an empty list', async () => {
    const { el } = await ready([], 'viewer');
    expect(el.querySelector('dnsy-mascot-empty')).not.toBeNull();
  });
});
