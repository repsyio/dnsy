import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { apiInterceptor } from './core/api.interceptor';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { App } from './app';
import { routes } from './app.routes';
import { NAV_ITEMS } from './layout/shell';

describe('App routing', () => {
  let ctrl: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter(routes),
        provideHttpClient(withInterceptors([apiInterceptor])),
        provideHttpClientTesting(),
      ],
    });
    ctrl = TestBed.inject(HttpTestingController);
  });

  it('creates the root component', () => {
    expect(TestBed.createComponent(App).componentInstance).toBeTruthy();
  });

  it('unauthenticated visit lands on the login page', async () => {
    const nav = TestBed.inject(Router).navigateByUrl('/zones');
    await vi.waitFor(() =>
      ctrl.expectOne('/api/v1/auth/me').flush(null, { status: 401, statusText: 'x' }),
    );
    await nav;
    expect(TestBed.inject(Router).url).toBe('/login?redirect=%2Fzones');
  });

  it('signed-in user gets the shell with a nav entry per page', async () => {
    const harness = await RouterTestingHarness.create();
    const nav = harness.navigateByUrl('/');
    await vi.waitFor(() =>
      ctrl
        .expectOne('/api/v1/auth/me')
        .flush({ id: 1, username: 'root', role: 'admin', created_at: 0, auth: 'session' }),
    );
    await nav;
    const el = harness.routeNativeElement as HTMLElement;
    expect(TestBed.inject(Router).url).toBe('/dashboard');
    expect(el.textContent).toContain('Dashboard');
    expect(NAV_ITEMS.length).toBe(13);
  });

  it('unknown path under the shell renders the 404 page', async () => {
    const harness = await RouterTestingHarness.create();
    const nav = harness.navigateByUrl('/nope/nothing');
    await vi.waitFor(() =>
      ctrl
        .expectOne('/api/v1/auth/me')
        .flush({ id: 1, username: 'root', role: 'viewer', created_at: 0, auth: 'session' }),
    );
    await nav;
    expect((harness.routeNativeElement as HTMLElement).textContent).toContain('404');
  });

  it.each([
    'dashboard',
    'zones',
    'filtering',
    'upstreams',
    'query-log',
    'users',
    'settings',
    'acl',
    'client-certs',
    'cache',
    'tokens',
    'profile',
  ])('lazy-loads the %s page', async (path) => {
    const harness = await RouterTestingHarness.create();
    const nav = harness.navigateByUrl('/' + path);
    await vi.waitFor(() =>
      ctrl
        .expectOne('/api/v1/auth/me')
        .flush({ id: 1, username: 'root', role: 'admin', created_at: 0, auth: 'session' }),
    );
    await nav;
    expect(TestBed.inject(Router).url).toBe('/' + path);
    expect((harness.routeNativeElement as HTMLElement).querySelector('h1')).toBeTruthy();
  });

  it('sign out posts logout and returns to login', async () => {
    const harness = await RouterTestingHarness.create();
    const nav = harness.navigateByUrl('/dashboard');
    await vi.waitFor(() =>
      ctrl
        .expectOne('/api/v1/auth/me')
        .flush({ id: 1, username: 'root', role: 'admin', created_at: 0, auth: 'session' }),
    );
    await nav;
    const btn = (harness.routeNativeElement as HTMLElement).querySelector<HTMLButtonElement>(
      'header div button',
    )!;
    btn.click();
    await vi.waitFor(() => ctrl.expectOne('/api/v1/auth/logout').flush({}));
    await vi.waitFor(() => expect(TestBed.inject(Router).url).toBe('/login'));
  });
});
