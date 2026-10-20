import { mount, problem, type, clickByText } from '../admin-shared/testing';
import { CertsPage } from './certs.page';

const HEX = 'ab'.repeat(32);
const CERT = {
  id: 1,
  sha256: HEX,
  label: 'laptop',
  enabled: true,
  created_at: 0,
  expired: false,
  expires_at: null,
};

async function ready(certs: unknown[] = [CERT]) {
  const ctx = mount(CertsPage);
  await ctx.fixture.whenStable();
  ctx.http.expectOne('/api/v1/client-certs').flush(certs);
  await ctx.fixture.whenStable();
  return ctx;
}

describe('CertsPage', () => {
  it('lists certificates with status badges', async () => {
    const { el } = await ready([
      CERT,
      { ...CERT, id: 2, label: 'old', expired: true, expires_at: 100 },
      { ...CERT, id: 3, label: 'off', enabled: false },
    ]);
    expect(el.querySelectorAll('tbody tr').length).toBe(3);
    expect(el.textContent).toContain('expired');
    expect(el.textContent).toContain('disabled');
    expect(el.textContent).toContain('never');
  });

  it('shows loading, error and empty states', async () => {
    const a = mount(CertsPage);
    await a.fixture.whenStable();
    expect(a.el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    a.http.expectOne('/api/v1/client-certs').flush('x', { status: 500, statusText: 'x' });
    await a.fixture.whenStable();
    expect(a.el.querySelector('dnsy-mascot-error')).not.toBeNull();
  });

  it('shows the empty state', async () => {
    const { el } = await ready([]);
    expect(el.querySelector('dnsy-mascot-empty')).not.toBeNull();
  });

  it('validates the form before sending', async () => {
    const { fixture, http, el } = await ready();
    type(el, '#cc-fp', 'abc');
    type(el, '#cc-exp', 'x');
    clickByText(el, 'Add');
    await fixture.whenStable();
    http.expectNone('/api/v1/client-certs');
    expect(el.textContent).toContain('64 hex digits');
    expect(el.textContent).toContain('A label is required');
  });

  it('adds a normalised fingerprint with an expiry and shows server errors', async () => {
    const { fixture, http, el } = await ready([]);
    type(el, '#cc-fp', HEX.toUpperCase().match(/../g)!.join(':'));
    type(el, '#cc-label', ' laptop ');
    type(el, '#cc-exp', '1970-01-02');
    clickByText(el, 'Add');
    const req = http.expectOne('/api/v1/client-certs');
    expect(req.request.body).toEqual({ sha256: HEX, label: 'laptop', expires_at: 86400 + 86399 });
    const p = problem(409, 'already allowed');
    req.flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('already allowed');
    clickByText(el, 'Add');
    http.expectOne('/api/v1/client-certs').flush(CERT, { status: 201, statusText: 'Created' });
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(1);
  });

  it('disables and enables a certificate', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Disable');
    const req = http.expectOne('/api/v1/client-certs/1');
    expect(req.request.body).toEqual({ enabled: false });
    req.flush({ ...CERT, enabled: false });
    await fixture.whenStable();
    expect(el.textContent).toContain('disabled');
    clickByText(el, 'Enable');
    const p = problem(404, 'missing');
    http.expectOne('/api/v1/client-certs/1').flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('missing');
  });

  it('removes only after confirmation', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Remove');
    await fixture.whenStable();
    http.expectNone('/api/v1/client-certs/1');
    clickByText(el.querySelector('app-confirm-dialog')!, 'Remove');
    http.expectOne('/api/v1/client-certs/1').flush(null, { status: 204, statusText: 'No Content' });
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-empty')).not.toBeNull();
  });

  it('keeps the row when removal fails', async () => {
    const { fixture, http, el } = await ready();
    clickByText(el, 'Remove');
    await fixture.whenStable();
    clickByText(el.querySelector('app-confirm-dialog')!, 'Remove');
    const p = problem(404, 'not found');
    http.expectOne('/api/v1/client-certs/1').flush(p.body, p.init);
    await fixture.whenStable();
    expect(el.textContent).toContain('not found');
    expect(el.querySelectorAll('tbody tr').length).toBe(1);
  });
});
