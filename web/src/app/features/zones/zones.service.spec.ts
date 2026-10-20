import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ZonesService, downloadText } from './zones.service';

describe('ZonesService', () => {
  let svc: ZonesService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    svc = TestBed.inject(ZonesService);
    http = TestBed.inject(HttpTestingController);
  });
  afterEach(() => http.verify());

  it('returns the ETag with a zone', () => {
    let got: unknown;
    svc.get('example.com.').subscribe((v) => (got = v));
    const req = http.expectOne('/api/v1/zones/example.com.');
    req.flush({ name: 'example.com.' }, { headers: { ETag: '"abc"' } });
    expect(got).toEqual({ body: { name: 'example.com.' }, etag: '"abc"' });
  });

  it('lists_zones_and_creates', () => {
    svc.list().subscribe();
    http.expectOne('/api/v1/zones').flush([]);
    svc.create({ name: 'a.', default_ttl: 1, soa: {} as never }).subscribe();
    const req = http.expectOne({ method: 'POST', url: '/api/v1/zones' });
    req.flush({}, { status: 201, statusText: 'Created' });
  });

  it('sends If-Match on writes and omits it without a tag', () => {
    svc.addRecord('z.', { name: '@', type: 'A', value: '192.0.2.1' }, '"t"').subscribe();
    const add = http.expectOne({ method: 'POST', url: '/api/v1/zones/z./records' });
    expect(add.request.headers.get('If-Match')).toBe('"t"');
    add.flush({}, { headers: { ETag: '"u"' } });

    svc.updateRecord('z.', 'r1', { name: '@', type: 'A', value: '192.0.2.2' }, null).subscribe();
    const upd = http.expectOne({ method: 'PUT', url: '/api/v1/zones/z./records/r1' });
    expect(upd.request.headers.has('If-Match')).toBe(false);
    upd.flush({});

    let tag: unknown;
    svc.deleteRecord('z.', 'r1', '*').subscribe((t) => (tag = t));
    const del = http.expectOne({ method: 'DELETE', url: '/api/v1/zones/z./records/r1' });
    expect(del.request.headers.get('If-Match')).toBe('*');
    del.flush(null, { status: 204, statusText: 'No Content', headers: { ETag: '"v"' } });
    expect(tag).toBe('"v"');

    svc.remove('z.', '"v"').subscribe();
    const rm = http.expectOne({ method: 'DELETE', url: '/api/v1/zones/z.' });
    expect(rm.request.headers.get('If-Match')).toBe('"v"');
    rm.flush(null, { status: 204, statusText: 'No Content' });
  });

  it('pages_records_and_filters_by_type', () => {
    svc.records('z.', { limit: 50, offset: 100, type: 'MX' }).subscribe();
    const req = http.expectOne((r) => r.url === '/api/v1/zones/z./records');
    expect(req.request.params.get('limit')).toBe('50');
    expect(req.request.params.get('offset')).toBe('100');
    expect(req.request.params.get('type')).toBe('MX');
    req.flush({ items: [], total: 0, limit: 50, offset: 100 });
    svc.records('z.', { limit: 50, offset: 0 }).subscribe();
    const plain = http.expectOne((r) => r.url === '/api/v1/zones/z./records');
    expect(plain.request.params.has('type')).toBe(false);
    plain.flush({ items: [], total: 0, limit: 50, offset: 0 });
  });

  it('requests_signed_export_as_text', () => {
    let text = '';
    svc.exportZone('z.', true).subscribe((t) => (text = t));
    const req = http.expectOne((r) => r.url === '/api/v1/zones/z./export');
    expect(req.request.params.get('signed')).toBe('true');
    req.flush('$ORIGIN z.');
    expect(text).toBe('$ORIGIN z.');
  });

  it('downloads_text_via_object_url', () => {
    const create = vi.fn(() => 'blob:x');
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    downloadText('a.zone', 'data');
    expect(create).toHaveBeenCalled();
    expect(click).toHaveBeenCalled();
    expect(revoke).toHaveBeenCalledWith('blob:x');
    click.mockRestore();
  });
});
