import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { apiInterceptor } from '../../core/api.interceptor';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { ZonesListPage } from './zones-list.page';

function setup() {
  TestBed.configureTestingModule({
    providers: [
      provideRouter([]),
      provideHttpClient(withInterceptors([apiInterceptor])),
      provideHttpClientTesting(),
    ],
  });
  const fixture = TestBed.createComponent(ZonesListPage);
  const http = TestBed.inject(HttpTestingController);
  const el = fixture.nativeElement as HTMLElement;
  return { fixture, http, el };
}

const ZONES = [
  { name: 'a.example.', serial: 3, record_count: 4, dnssec_enabled: true, load_error: null },
  { name: 'b.example.', serial: 1, record_count: 2, dnssec_enabled: false, load_error: 'bad file' },
];

describe('ZonesListPage', () => {
  it('shows loading then rows with signed and load error badges', async () => {
    const { fixture, http, el } = setup();
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-loading')).not.toBeNull();
    http.expectOne('/api/v1/zones').flush(ZONES);
    await fixture.whenStable();
    expect(el.querySelectorAll('tbody tr').length).toBe(2);
    expect(el.textContent).toContain('signed');
    expect(el.textContent).toContain('load error');
    expect(el.textContent).toContain('bad file');
    expect(el.querySelector('a')?.getAttribute('href')).toBe('/zones/a.example.');
  });

  it('shows the empty mascot', async () => {
    const { fixture, http, el } = setup();
    await fixture.whenStable();
    http.expectOne('/api/v1/zones').flush([]);
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-empty')).not.toBeNull();
  });

  it('shows the error mascot and retries', async () => {
    const { fixture, http, el } = setup();
    await fixture.whenStable();
    http.expectOne('/api/v1/zones').flush(null, { status: 500, statusText: 'x' });
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-error')).not.toBeNull();
    el.querySelector<HTMLButtonElement>('dnsy-mascot-error button')?.click();
    await fixture.whenStable();
    http.expectOne('/api/v1/zones').flush([]);
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-empty')).not.toBeNull();
  });

  it('creates a zone through the dialog and navigates to it', async () => {
    const { fixture, http, el } = setup();
    const nav = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    await fixture.whenStable();
    http.expectOne('/api/v1/zones').flush([]);
    await fixture.whenStable();
    el.querySelector<HTMLButtonElement>('button.btn')?.click();
    await fixture.whenStable();
    const type = (id: string, v: string) => {
      const input = el.querySelector<HTMLInputElement>(`#${id}`)!;
      input.value = v;
      input.dispatchEvent(new Event('input'));
    };
    type('zone-name', 'new.example.');
    type('zone-ns', 'ns1.new.example.');
    type('zone-mname', 'ns1.new.example.');
    type('zone-rname', 'hostmaster.new.example.');
    el.querySelector('form')?.dispatchEvent(new Event('submit'));
    await fixture.whenStable();
    const req = http.expectOne({ method: 'POST', url: '/api/v1/zones' });
    expect(req.request.body.name).toBe('new.example.');
    expect(req.request.body.records).toEqual([
      { name: '@', type: 'NS', value: 'ns1.new.example.' },
    ]);
    req.flush({ name: 'new.example.' }, { status: 201, statusText: 'Created' });
    await fixture.whenStable();
    expect(nav).toHaveBeenCalledWith(['/zones', 'new.example.']);
  });

  it('shows the server message when create fails and validates first', async () => {
    const { fixture, http, el } = setup();
    await fixture.whenStable();
    http.expectOne('/api/v1/zones').flush([]);
    await fixture.whenStable();
    el.querySelector<HTMLButtonElement>('button.btn')?.click();
    await fixture.whenStable();
    el.querySelector('form')?.dispatchEvent(new Event('submit'));
    await fixture.whenStable();
    http.expectNone('/api/v1/zones');
    expect(el.textContent).toContain('At least one name server');
    for (const [id, v] of [
      ['zone-name', 'x.example.'],
      ['zone-ns', 'ns.x.example.'],
      ['zone-mname', 'ns.x.example.'],
      ['zone-rname', 'h.x.example.'],
    ]) {
      const input = el.querySelector<HTMLInputElement>(`#${id}`)!;
      input.value = v;
      input.dispatchEvent(new Event('input'));
    }
    el.querySelector('form')?.dispatchEvent(new Event('submit'));
    await fixture.whenStable();
    http.expectOne({ method: 'POST', url: '/api/v1/zones' }).flush(
      { type: 'x/conflict', title: 'Conflict', status: 409, detail: 'zone exists' },
      {
        status: 409,
        statusText: 'Conflict',
        headers: { 'content-type': 'application/problem+json' },
      },
    );
    await fixture.whenStable();
    expect(el.querySelector('[role="alert"]')?.textContent).toContain('zone exists');
    el.querySelectorAll<HTMLButtonElement>('button').forEach((b) => {
      if (b.textContent?.trim() === 'Cancel') b.click();
    });
    await fixture.whenStable();
    expect(el.querySelector('app-create-zone-dialog')).toBeNull();
  });
});
