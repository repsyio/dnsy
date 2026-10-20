import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { apiInterceptor } from '../../core/api.interceptor';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { ZoneDetailPage } from './zone-detail.page';

const ZONE = {
  name: 'example.com.',
  default_ttl: 3600,
  record_count: 1,
  dnssec_enabled: true,
  load_error: null,
  soa: {},
};
const REC = { id: 'r1', name: 'www.example.com.', type: 'A', ttl: 300, value: '192.0.2.1' };
const URL_ = globalThis.URL;
const URL = '/api/v1/zones/example.com.';
const problem = (status: number, detail: string) => ({
  body: { type: 'x/p', title: 'T', status, detail },
  opts: { status, statusText: 'x', headers: { 'content-type': 'application/problem+json' } },
});

async function setup() {
  TestBed.configureTestingModule({
    providers: [
      provideRouter([]),
      provideHttpClient(withInterceptors([apiInterceptor])),
      provideHttpClientTesting(),
    ],
  });
  const fixture = TestBed.createComponent(ZoneDetailPage);
  fixture.componentRef.setInput('name', 'example.com.');
  const http = TestBed.inject(HttpTestingController);
  const el = fixture.nativeElement as HTMLElement;
  const settle = async () => {
    await fixture.whenStable();
  };
  const flushLoad = async (items: unknown[] = [REC], total = items.length, tag = '"e1"') => {
    await settle();
    http.expectOne(URL).flush(ZONE, { headers: { ETag: tag } });
    await settle();
    http
      .expectOne((r) => r.url === `${URL}/records`)
      .flush({ items, total, limit: 50, offset: 0 }, { headers: { ETag: tag } });
    await settle();
  };
  const button = (label: string): HTMLButtonElement =>
    Array.from(el.querySelectorAll('button')).find(
      (b) => b.textContent?.trim() === label || b.getAttribute('aria-label') === label,
    ) as HTMLButtonElement;
  const type = (id: string, v: string) => {
    const input = el.querySelector<HTMLInputElement>(`[id$="${id}"]`)!;
    input.value = v;
    input.dispatchEvent(new Event('input'));
  };
  return { fixture, http, el, settle, flushLoad, button, type };
}

describe('ZoneDetailPage', () => {
  it('renders the record table with the DNSSEC tab slot untouched', async () => {
    const t = await setup();
    await t.settle();
    expect(t.el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    await t.flushLoad();
    expect(t.el.querySelectorAll('tbody tr').length).toBe(1);
    expect(t.el.textContent).toContain('192.0.2.1');
    expect(t.el.querySelector('[role="tablist"]')).not.toBeNull();
    expect(t.button('Download signed')).toBeTruthy();
  });

  it('shows 404 and error states', async () => {
    const t = await setup();
    await t.settle();
    t.http.expectOne(URL).flush(null, { status: 404, statusText: 'Not Found' });
    await t.settle();
    expect(t.el.querySelector('dnsy-mascot-not-found')).not.toBeNull();

    TestBed.resetTestingModule();
    const u = await setup();
    await u.settle();
    u.http.expectOne(URL).flush(null, { status: 500, statusText: 'x' });
    await u.settle();
    expect(u.el.querySelector('dnsy-mascot-error')).not.toBeNull();
  });

  it('shows the empty mascot and the load error banner', async () => {
    const t = await setup();
    await t.flushLoad([]);
    expect(t.el.querySelector('dnsy-mascot-empty')).not.toBeNull();
  });

  it('adds a record with If-Match and the current ETag', async () => {
    const t = await setup();
    await t.flushLoad();
    t.button('Add record').click();
    await t.settle();
    t.type('-name', 'api');
    t.type('-value', 'not an ip');
    t.el.querySelector('app-record-editor form')?.dispatchEvent(new Event('submit'));
    await t.settle();
    t.http.expectNone(`${URL}/records`);
    expect(t.el.textContent).toContain('Enter an IPv4 address');
    t.type('-value', '192.0.2.9');
    t.type('-ttl', '120');
    t.el.querySelector('app-record-editor form')?.dispatchEvent(new Event('submit'));
    await t.settle();
    const req = t.http.expectOne({ method: 'POST', url: `${URL}/records` });
    expect(req.request.headers.get('If-Match')).toBe('"e1"');
    expect(req.request.body).toEqual({ name: 'api', type: 'A', value: '192.0.2.9', ttl: 120 });
    req.flush({}, { status: 201, statusText: 'Created', headers: { ETag: '"e2"' } });
    await t.settle();
    t.http.expectOne(URL).flush(ZONE, { headers: { ETag: '"e2"' } });
    await t.settle();
    t.http
      .expectOne((r) => r.url === `${URL}/records`)
      .flush({ items: [REC], total: 1, limit: 50, offset: 0 }, { headers: { ETag: '"e2"' } });
    await t.settle();
    expect(t.el.querySelector('dnsy-mascot-success')).not.toBeNull();
    expect(t.el.querySelector('app-record-editor')).toBeNull();
  });

  it('edits a record inline and shows server validation errors', async () => {
    const t = await setup();
    await t.flushLoad();
    t.button('Edit A record www.example.com.').click();
    await t.settle();
    expect(t.el.querySelector<HTMLInputElement>('[id$="-value"]')?.value).toBe('192.0.2.1');
    t.type('-value', '192.0.2.77');
    t.el.querySelector('app-record-editor form')?.dispatchEvent(new Event('submit'));
    await t.settle();
    const p = problem(422, 'CNAME and other data');
    t.http.expectOne({ method: 'PUT', url: `${URL}/records/r1` }).flush(p.body, p.opts);
    await t.settle();
    expect(t.el.querySelector('app-record-editor [role="alert"]')?.textContent).toContain(
      'CNAME and other data',
    );
    t.button('Cancel').click();
    await t.settle();
    expect(t.el.querySelector('app-record-editor')).toBeNull();
  });

  it('handles a 412 conflict: reload latest', async () => {
    const t = await setup();
    await t.flushLoad();
    t.button('Delete A record www.example.com.').click();
    await t.settle();
    t.el.querySelectorAll<HTMLButtonElement>('app-confirm-dialog button')[1].click();
    await t.settle();
    const p = problem(412, 'stale');
    t.http.expectOne({ method: 'DELETE', url: `${URL}/records/r1` }).flush(p.body, p.opts);
    await t.settle();
    expect(t.el.querySelector('[role="alert"]')?.textContent).toContain('changed elsewhere');
    expect(t.el.querySelector('app-confirm-dialog')).toBeNull();
    t.button('Reload latest').click();
    await t.settle();
    t.http.expectOne(URL).flush(ZONE, { headers: { ETag: '"e9"' } });
    await t.settle();
    t.http
      .expectOne((r) => r.url === `${URL}/records`)
      .flush({ items: [], total: 0, limit: 50, offset: 0 }, { headers: { ETag: '"e9"' } });
    await t.settle();
    expect(t.el.textContent).not.toContain('changed elsewhere');
  });

  it('handles a 412 conflict: overwrite anyway retries with If-Match *', async () => {
    const t = await setup();
    await t.flushLoad();
    t.button('Delete A record www.example.com.').click();
    await t.settle();
    t.el.querySelectorAll<HTMLButtonElement>('app-confirm-dialog button')[1].click();
    await t.settle();
    const p = problem(412, 'stale');
    t.http.expectOne({ method: 'DELETE', url: `${URL}/records/r1` }).flush(p.body, p.opts);
    await t.settle();
    t.button('Overwrite anyway').click();
    await t.settle();
    const retry = t.http.expectOne({ method: 'DELETE', url: `${URL}/records/r1` });
    expect(retry.request.headers.get('If-Match')).toBe('*');
    retry.flush(null, { status: 204, statusText: 'No Content', headers: { ETag: '"e3"' } });
    await t.settle();
    t.http.expectOne(URL).flush(ZONE, { headers: { ETag: '"e3"' } });
    await t.settle();
    t.http
      .expectOne((r) => r.url === `${URL}/records`)
      .flush({ items: [], total: 0, limit: 50, offset: 0 }, { headers: { ETag: '"e3"' } });
  });

  it('deleting a zone needs the typed name, then navigates away', async () => {
    const t = await setup();
    const nav = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    await t.flushLoad();
    t.button('Delete zone').click();
    await t.settle();
    const confirm = Array.from(t.el.querySelectorAll('app-confirm-dialog button')).find(
      (b) => b.textContent?.trim() === 'Delete',
    ) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    const input = t.el.querySelector<HTMLInputElement>('#confirm-phrase')!;
    input.value = 'example.com.';
    input.dispatchEvent(new Event('input'));
    await t.settle();
    expect(confirm.disabled).toBe(false);
    confirm.click();
    await t.settle();
    const req = t.http.expectOne({ method: 'DELETE', url: URL });
    expect(req.request.headers.get('If-Match')).toBe('"e1"');
    req.flush(null, { status: 204, statusText: 'No Content' });
    await t.settle();
    expect(nav).toHaveBeenCalledWith(['/zones']);
  });

  it('downloads the BIND export, signed and unsigned, and reports failures', async () => {
    const t = await setup();
    const saved: string[] = [];
    Object.assign(URL_, { createObjectURL: () => 'blob:x', revokeObjectURL: () => {} });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      saved.push(this.download);
    });
    await t.flushLoad();
    t.button('Download BIND').click();
    await t.settle();
    let req = t.http.expectOne((r) => r.url === `${URL}/export`);
    expect(req.request.params.get('signed')).toBe('false');
    req.flush('$ORIGIN example.com.');
    await t.settle();
    expect(saved).toEqual(['example.com.zone']);
    t.button('Download signed').click();
    await t.settle();
    req = t.http.expectOne((r) => r.url === `${URL}/export`);
    expect(req.request.params.get('signed')).toBe('true');
    req.flush('x');
    await t.settle();
    expect(saved).toEqual(['example.com.zone', 'example.com.signed.zone']);
    t.button('Download BIND').click();
    await t.settle();
    t.http
      .expectOne((r) => r.url === `${URL}/export`)
      .flush('no', { status: 409, statusText: 'x' });
    await t.settle();
    expect(t.el.querySelector('[role="alert"]')?.textContent).toBeTruthy();
    click.mockRestore();
  });

  it('filters by type and pages', async () => {
    const t = await setup();
    await t.flushLoad([REC], 120);
    expect(t.el.textContent).toContain('1-1 of 120');
    t.button('Next').click();
    await t.settle();
    let req = t.http.expectOne((r) => r.url === `${URL}/records`);
    expect(req.request.params.get('offset')).toBe('50');
    req.flush({ items: [REC], total: 120, limit: 50, offset: 50 });
    await t.settle();
    t.button('Previous').click();
    await t.settle();
    t.http
      .expectOne((r) => r.url === `${URL}/records`)
      .flush({ items: [REC], total: 120, limit: 50, offset: 0 });
    await t.settle();
    const sel = t.el.querySelector<HTMLSelectElement>('#type-filter')!;
    sel.value = 'MX';
    sel.dispatchEvent(new Event('change'));
    await t.settle();
    req = t.http.expectOne((r) => r.url === `${URL}/records`);
    expect(req.request.params.get('type')).toBe('MX');
    req.flush({ items: [], total: 0, limit: 50, offset: 0 });
  });
});
