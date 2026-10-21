import { clickByText, mount, problem, type } from '../admin-shared/testing';
import { ValidationPage } from './validation.page';

const SETTINGS = {
  validation: 'strict',
  negative_trust_anchors: ['broken.example.'],
  negative_trust_anchor_entries: [{ name: 'broken.example.', expires_at: null }],
  trust_anchors: [
    { owner: '.', key_tag: 20326, algorithm: 8, kind: 'ds', digest_type: 2, digest: 'E06D' },
    { owner: 'a.', key_tag: 1, algorithm: 13, kind: 'dnskey' },
  ],
};
const STATUS = {
  clock_trusted: true,
  window_ms: 86_400_000,
  counters: {},
  secure: 12,
  bogus: 3,
  signed_zones: 2,
};

async function ready(settings: object = SETTINGS, status: object = STATUS) {
  const ctx = mount(ValidationPage);
  await ctx.fixture.whenStable();
  ctx.http.expectOne('/api/v1/settings/dnssec').flush(settings);
  await ctx.fixture.whenStable();
  ctx.http.expectOne('/api/v1/dnssec/status').flush(status);
  await ctx.fixture.whenStable();
  return ctx;
}

const radio = (el: HTMLElement, m: string) => el.querySelector<HTMLInputElement>(`#vm-${m}`)!;

describe('ValidationPage', () => {
  it('shows loading, an error with retry, then settings and counters', async () => {
    const ctx = mount(ValidationPage);
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    const p = problem(503, 'not wired');
    ctx.http.expectOne('/api/v1/settings/dnssec').flush(p.body, p.init);
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-error')).not.toBeNull();
    clickByText(ctx.el, 'Retry');
    ctx.http.expectOne('/api/v1/settings/dnssec').flush(SETTINGS);
    await ctx.fixture.whenStable();
    ctx.http.expectOne('/api/v1/dnssec/status').flush('x', { status: 500, statusText: 'x' });
    await ctx.fixture.whenStable();
    expect(radio(ctx.el, 'strict').checked).toBe(true);
    expect(ctx.el.textContent).toContain('recommended');
    expect(ctx.el.textContent).toContain('20326');
    expect(ctx.el.textContent).toContain('SHA-256 E06D');
  });

  it('shows counters and the clock warning', async () => {
    const ctx = await ready(SETTINGS, { ...STATUS, clock_trusted: false });
    expect(ctx.el.textContent).toContain('24 h');
    expect(ctx.el.textContent).toContain('clock is before the build time');
  });

  it('weakening needs confirmation; strengthening does not', async () => {
    const ctx = await ready();
    radio(ctx.el, 'off').dispatchEvent(new Event('change'));
    await ctx.fixture.whenStable();
    ctx.http.expectNone('/api/v1/settings/dnssec');
    expect(ctx.el.textContent).toContain('spoofed DNS data reaches your clients');
    clickByText(ctx.el, 'Cancel');
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('app-confirm-dialog')).toBeNull();

    radio(ctx.el, 'permissive').dispatchEvent(new Event('change'));
    await ctx.fixture.whenStable();
    clickByText(ctx.el, 'Set permissive');
    const req = ctx.http.expectOne('/api/v1/settings/dnssec');
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual({ validation: 'permissive' });
    req.flush({ ...SETTINGS, validation: 'permissive' });
    await ctx.fixture.whenStable();
    ctx.http.expectOne('/api/v1/dnssec/status').flush(STATUS);
    await ctx.fixture.whenStable();
    expect(ctx.el.textContent).toContain('Validation mode is now permissive');

    radio(ctx.el, 'strict').dispatchEvent(new Event('change'));
    const up = ctx.http.expectOne('/api/v1/settings/dnssec');
    expect(up.request.body).toEqual({ validation: 'strict' });
    const p = problem(503, 'unavailable');
    up.flush(p.body, p.init);
    await ctx.fixture.whenStable();
    expect(ctx.el.textContent).toContain('unavailable');
    radio(ctx.el, 'permissive').dispatchEvent(new Event('change'));
    ctx.http.expectNone('/api/v1/settings/dnssec');
  });

  it('adds and removes negative trust anchors', async () => {
    const ctx = await ready();
    type(ctx.el, '#nta-name', 'a..b');
    ctx.el.querySelector('form')!.dispatchEvent(new Event('submit'));
    await ctx.fixture.whenStable();
    expect(ctx.el.textContent).toContain('Use labels');
    ctx.http.expectNone('/api/v1/settings/dnssec');

    type(ctx.el, '#nta-name', 'Other.Test');
    ctx.el.querySelector('form')!.dispatchEvent(new Event('submit'));
    const add = ctx.http.expectOne('/api/v1/settings/dnssec');
    expect(add.request.body).toEqual({
      negative_trust_anchors: [
        { name: 'broken.example.', expires_at: null },
        { name: 'other.test.', expires_at: null },
      ],
    });
    add.flush({
      ...SETTINGS,
      negative_trust_anchors: ['broken.example.', 'other.test.'],
      negative_trust_anchor_entries: [
        { name: 'broken.example.', expires_at: null },
        { name: 'other.test.', expires_at: null },
      ],
    });
    await ctx.fixture.whenStable();
    ctx.http.expectOne('/api/v1/dnssec/status').flush(STATUS);
    await ctx.fixture.whenStable();
    expect(ctx.el.textContent).toContain('other.test.');

    ctx.el
      .querySelector<HTMLElement>('[aria-label="Remove negative trust anchor other.test."]')!
      .click();
    await ctx.fixture.whenStable();
    clickByText(ctx.el.querySelector('app-confirm-dialog')!, 'Remove');
    const rm = ctx.http.expectOne('/api/v1/settings/dnssec');
    expect(rm.request.body).toEqual({
      negative_trust_anchors: [{ name: 'broken.example.', expires_at: null }],
    });
    rm.flush({ ...SETTINGS, negative_trust_anchors: [], negative_trust_anchor_entries: [] });
    await ctx.fixture.whenStable();
    ctx.http.expectOne('/api/v1/dnssec/status').flush(STATUS);
    await ctx.fixture.whenStable();
    expect(ctx.el.textContent).toContain('No negative trust anchors');
  });

  it('adds an anchor with an expiry and shows when each anchor expires', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000);
    const withExpiry = {
      ...SETTINGS,
      negative_trust_anchors: ['broken.example.', 'lab.test.'],
      negative_trust_anchor_entries: [
        { name: 'broken.example.', expires_at: null },
        { name: 'lab.test.', expires_at: 1_700_003_600 },
      ],
    };
    const ctx = await ready(withExpiry);
    expect(ctx.el.textContent).toContain('no expiry');
    expect(ctx.el.textContent).toContain('expires');

    type(ctx.el, '#nta-name', 'x.test');
    type(ctx.el, '#nta-hours', '2.5');
    ctx.el.querySelector('form')!.dispatchEvent(new Event('submit'));
    await ctx.fixture.whenStable();
    expect(ctx.el.textContent).toContain('whole number of hours');
    ctx.http.expectNone('/api/v1/settings/dnssec');

    type(ctx.el, '#nta-hours', '2');
    ctx.el.querySelector('form')!.dispatchEvent(new Event('submit'));
    const req = ctx.http.expectOne('/api/v1/settings/dnssec');
    expect(req.request.body).toEqual({
      negative_trust_anchors: [
        { name: 'broken.example.', expires_at: null },
        { name: 'lab.test.', expires_at: 1_700_003_600 },
        { name: 'x.test.', expires_at: 1_700_007_200 },
      ],
    });
    req.flush(withExpiry);
    await ctx.fixture.whenStable();
    ctx.http.expectOne('/api/v1/dnssec/status').flush(STATUS);
    vi.restoreAllMocks();
  });

  it('shows the empty trust anchor state', async () => {
    const ctx = await ready({ ...SETTINGS, trust_anchors: [] });
    expect(ctx.el.textContent).toContain('No trust anchors configured');
  });
});
