import { TestBed } from '@angular/core/testing';
import { clickByText, mount, problem, type } from '../admin-shared/testing';
import { ZoneDnssecTab } from './zone-dnssec-tab';

const URL = '/api/v1/zones/example.com./dnssec';

const key = (over = {}) => ({
  id: 1,
  role: 'csk',
  algorithm: 13,
  key_tag: 4242,
  state: 'active',
  created_at: 1_700_000_000,
  active_at: 1_700_000_100,
  ...over,
});

const view = (over = {}) => ({
  enabled: true,
  algorithm: 13,
  key_layout: 'csk',
  denial: 'nsec3',
  nsec3: { salt: '', iterations: 0, opt_out: false, allow_nonzero_iterations: false },
  signature_validity_days: 14,
  refresh_days: 5,
  dnskey_ttl: 3600,
  keys: [key()],
  rollover: { state: 'idle' },
  keys_encrypted: true,
  next_resign: 1_700_100_000,
  ...over,
});

const DS = {
  zone: 'example.com.',
  ds: [
    { key_id: 1, key_tag: 4242, algorithm: 13, digest_type: 4, digest: 'BB', record: 'SHA384-REC' },
    { key_id: 1, key_tag: 4242, algorithm: 13, digest_type: 2, digest: 'AA', record: 'SHA256-REC' },
  ],
  dnskey: [
    {
      key_id: 1,
      key_tag: 4242,
      flags: 257,
      protocol: 3,
      algorithm: 13,
      public_key: 'x',
      record: 'KEY-REC',
    },
  ],
};

async function setup(v: object, withDs = true) {
  const ctx = mount(ZoneDnssecTab);
  ctx.fixture.componentRef.setInput('zone', 'example.com.');
  const changed = vi.fn();
  ctx.fixture.componentInstance.changed.subscribe(changed);
  await ctx.fixture.whenStable();
  ctx.http.expectOne(URL).flush(v);
  await ctx.fixture.whenStable();
  if (withDs && (v as { enabled: boolean }).enabled) {
    ctx.http.expectOne(`${URL}/ds`).flush(DS);
    await ctx.fixture.whenStable();
  }
  return { ...ctx, changed };
}

describe('ZoneDnssecTab', () => {
  it('shows loading, then an error with retry', async () => {
    const ctx = mount(ZoneDnssecTab);
    ctx.fixture.componentRef.setInput('zone', 'example.com.');
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    ctx.http.expectOne(URL).flush(...(Object.values(problem(500, 'boom')) as [object, object]));
    await ctx.fixture.whenStable();
    expect(ctx.el.querySelector('dnsy-mascot-error')).not.toBeNull();
    clickByText(ctx.el, 'Retry');
    ctx.http.expectOne(URL).flush(view({ enabled: false }));
    await ctx.fixture.whenStable();
    expect(ctx.el.textContent).toContain('Sign this zone');
  });

  it('unencrypted_keys_warning_shown', async () => {
    const t = await setup(view({ keys_encrypted: false }));
    expect(t.el.querySelector('[role="alert"]')?.textContent).toContain('not encrypted');
    TestBed.resetTestingModule();
    const u = await setup(view({ keys_encrypted: true }));
    expect(u.el.textContent).not.toContain('not encrypted');
  });

  it('enables signing after a confirmation that explains the registrar step', async () => {
    const t = await setup(view({ enabled: false, keys: [] }));
    t.el.querySelector<HTMLElement>('#dn-nsec')!.click();
    t.el.querySelector<HTMLSelectElement>('#dn-alg')!.value = '15';
    t.el.querySelector('#dn-alg')!.dispatchEvent(new Event('change'));
    t.el.querySelector<HTMLSelectElement>('#dn-layout')!.value = 'ksk_zsk';
    t.el.querySelector('#dn-layout')!.dispatchEvent(new Event('change'));
    clickByText(t.el, 'Enable DNSSEC signing');
    await t.fixture.whenStable();
    expect(t.el.textContent).toContain('publish the DS record at your registrar');
    t.http.expectNone(URL);
    clickByText(t.el, 'Enable signing');
    const req = t.http.expectOne(URL);
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({
      enabled: true,
      algorithm: 15,
      key_layout: 'ksk_zsk',
      denial: 'nsec',
    });
    req.flush(view());
    await t.fixture.whenStable();
    t.http.expectOne(`${URL}/ds`).flush(DS);
    await t.fixture.whenStable();
    expect(t.changed).toHaveBeenCalled();
    expect(t.el.textContent).toContain('Signing enabled');
  });

  it('sends NSEC3 parameters and rejects bad ones before any request', async () => {
    const t = await setup(view({ enabled: false, keys: [] }));
    type(t.el, '#dn-salt', 'zz');
    clickByText(t.el, 'Enable DNSSEC signing');
    await t.fixture.whenStable();
    expect(t.el.textContent).toContain('hexadecimal');
    expect(t.el.querySelector('app-confirm-dialog')).toBeNull();
    type(t.el, '#dn-salt', 'ab');
    type(t.el, '#dn-iter', '3');
    t.el.querySelector<HTMLElement>('#dn-nonzero')!.click();
    t.el.querySelector<HTMLElement>('#dn-optout')!.click();
    clickByText(t.el, 'Enable DNSSEC signing');
    await t.fixture.whenStable();
    clickByText(t.el, 'Enable signing');
    const req = t.http.expectOne(URL);
    expect((req.request.body as { nsec3: object }).nsec3).toEqual({
      salt: 'ab',
      iterations: 3,
      allow_nonzero_iterations: true,
      opt_out: true,
    });
  });

  it('shows a server rejection in the dialog', async () => {
    const t = await setup(view({ enabled: false, keys: [] }));
    clickByText(t.el, 'Enable DNSSEC signing');
    await t.fixture.whenStable();
    clickByText(t.el, 'Enable signing');
    const p = problem(422, 'bad policy');
    t.http.expectOne(URL).flush(p.body, p.init);
    await t.fixture.whenStable();
    expect(t.el.querySelector('app-confirm-dialog')?.textContent).toContain('bad policy');
    clickByText(t.el, 'Cancel');
    await t.fixture.whenStable();
    expect(t.el.querySelector('app-confirm-dialog')).toBeNull();
  });

  it('disabling needs the zone name typed and warns about the DS', async () => {
    const t = await setup(view());
    expect(t.el.textContent).toContain('4242');
    clickByText(t.el, 'Disable signing');
    await t.fixture.whenStable();
    expect(t.el.textContent).toContain('Remove the DS record at your registrar first');
    const confirm = Array.from(t.el.querySelectorAll('button')).filter(
      (b) => b.textContent?.trim() === 'Disable signing',
    )[1];
    expect(confirm.disabled).toBe(true);
    type(t.el, '#confirm-phrase', 'example.com.');
    t.fixture.detectChanges();
    confirm.click();
    const req = t.http.expectOne(URL);
    expect(req.request.body).toEqual({ enabled: false });
    req.flush(view({ enabled: false, keys: [] }));
    await t.fixture.whenStable();
    expect(t.changed).toHaveBeenCalled();
    expect(t.el.textContent).toContain('Sign this zone');
  });

  it('rollover_requires_confirmation', async () => {
    const t = await setup(view());
    clickByText(t.el, 'Start rollover');
    await t.fixture.whenStable();
    t.http.expectNone(`${URL}/keys/1/rollover`);
    expect(t.el.textContent).toContain('new key is generated');
    clickByText(t.el, 'Cancel');
    await t.fixture.whenStable();
    t.http.expectNone(`${URL}/keys/1/rollover`);
    clickByText(t.el, 'Start rollover');
    await t.fixture.whenStable();
    const confirm = Array.from(t.el.querySelectorAll('app-confirm-dialog button')).find(
      (b) => b.textContent?.trim() === 'Start rollover',
    ) as HTMLElement;
    confirm.click();
    const req = t.http.expectOne(`${URL}/keys/1/rollover`);
    expect(req.request.method).toBe('POST');
    req.flush({}, { status: 202, statusText: 'Accepted' });
    await t.fixture.whenStable();
    t.http.expectOne(URL).flush(view({ rollover: { state: 'in_progress', role: 'csk' } }));
    await t.fixture.whenStable();
    t.http.expectOne(`${URL}/ds`).flush(DS);
    await t.fixture.whenStable();
    expect(t.el.textContent).toContain('Rollover started');
    expect(t.el.textContent).toContain('in progress');
    expect(t.el.textContent).not.toContain('Start rollover');
  });

  it('confirms the DS at the registrar', async () => {
    const t = await setup(
      view({
        rollover: { state: 'awaiting_ds_confirmation', role: 'csk', new_key_id: 2 },
        keys: [key(), key({ id: 2, state: 'published', key_tag: 7, published_at: 1_700_000_200 })],
      }),
    );
    expect(t.el.textContent).toContain('waiting for you to publish');
    expect(t.el.querySelectorAll('[aria-label^="DS confirmed at registrar"]').length).toBe(2);
    t.el.querySelector<HTMLElement>('[aria-label="DS confirmed at registrar for key 7"]')!.click();
    await t.fixture.whenStable();
    clickByText(t.el, 'DS is published');
    const req = t.http.expectOne(`${URL}/keys/2/ds-confirmed`);
    req.flush(null, { status: 204, statusText: 'No Content' });
    await t.fixture.whenStable();
    t.http.expectOne(URL).flush(view());
    await t.fixture.whenStable();
    t.http.expectOne(`${URL}/ds`).flush(DS);
    await t.fixture.whenStable();
    expect(t.el.textContent).toContain('DS confirmed.');
  });

  it('copies the SHA-256 DS first and the DNSKEY on request', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    const t = await setup(view());
    const recs = Array.from(t.el.querySelectorAll('li code')).map((c) => c.textContent?.trim());
    expect(recs).toEqual(['SHA256-REC', 'SHA384-REC', 'KEY-REC']);
    clickByText(t.el, 'Copy for registrar (SHA-256)');
    expect(writeText).toHaveBeenLastCalledWith('SHA256-REC');
    await t.fixture.whenStable();
    expect(t.el.textContent).toContain('DS record copied');
    t.el.querySelector<HTMLElement>('[aria-label="Copy DNSKEY record for key 4242"]')!.click();
    expect(writeText).toHaveBeenLastCalledWith('KEY-REC');
    vi.unstubAllGlobals();
  });

  it('reports a blocked or missing clipboard', async () => {
    vi.stubGlobal('navigator', {
      clipboard: { writeText: vi.fn().mockRejectedValue(new Error('no')) },
    });
    const t = await setup(view());
    clickByText(t.el, 'Copy for registrar (SHA-256)');
    await t.fixture.whenStable();
    expect(t.el.textContent).toContain('Copy was blocked');
    vi.stubGlobal('navigator', {});
    clickByText(t.el, 'Copy for registrar (SHA-256)');
    await t.fixture.whenStable();
    expect(t.el.textContent).toContain('not available');
    vi.unstubAllGlobals();
  });

  it('shows empty DS state and a DS load error', async () => {
    const t = await setup(view(), false);
    const p = problem(503, 'down');
    t.http.expectOne(`${URL}/ds`).flush(p.body, p.init);
    await t.fixture.whenStable();
    expect(t.el.textContent).toContain('down');
    TestBed.resetTestingModule();
    const u = await setup(view(), false);
    u.http.expectOne(`${URL}/ds`).flush({ zone: 'example.com.', ds: [], dnskey: [] });
    await u.fixture.whenStable();
    expect(u.el.textContent).toContain('No DS available yet');
  });

  it('downloads the signed export', async () => {
    const t = await setup(view());
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);
    URL_STUB();
    clickByText(t.el, 'Download signed export');
    const req = t.http.expectOne((r) => r.url.endsWith('/zones/example.com./export'));
    expect(req.request.params.get('signed')).toBe('true');
    req.flush('zone text');
    expect(click).toHaveBeenCalled();
    clickByText(t.el, 'Download signed export');
    const p = problem(500, 'nope');
    const r2 = t.http.expectOne((r) => r.url.endsWith('/export'));
    r2.flush(p.body, p.init);
    await t.fixture.whenStable();
    expect(t.el.textContent).toContain('Http failure');
    click.mockRestore();
  });
});

function URL_STUB() {
  globalThis.URL.createObjectURL = vi.fn(() => 'blob:x');
  globalThis.URL.revokeObjectURL = vi.fn();
}
