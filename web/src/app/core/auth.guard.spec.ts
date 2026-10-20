import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { apiInterceptor } from './api.interceptor';
import { TestBed } from '@angular/core/testing';
import { RouterStateSnapshot, Router, UrlTree, provideRouter } from '@angular/router';
import { authGuard } from './auth.guard';

describe('authGuard', () => {
  let ctrl: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withInterceptors([apiInterceptor])),
        provideHttpClientTesting(),
      ],
    });
    ctrl = TestBed.inject(HttpTestingController);
  });

  const run = () =>
    TestBed.runInInjectionContext(() =>
      authGuard({} as never, { url: '/zones' } as RouterStateSnapshot),
    ) as Promise<boolean | UrlTree>;

  it('auth_guard_redirects_when_unauthenticated', async () => {
    const result = run();
    await vi.waitFor(() =>
      ctrl.expectOne('/api/v1/auth/me').flush(null, { status: 401, statusText: 'x' }),
    );
    const tree = (await result) as UrlTree;
    expect(TestBed.inject(Router).serializeUrl(tree)).toBe('/login?redirect=%2Fzones');
  });

  it('auth_guard_allows_signed_in_user_and_caches', async () => {
    const result = run();
    await vi.waitFor(() =>
      ctrl
        .expectOne('/api/v1/auth/me')
        .flush({ id: 1, username: 'a', role: 'admin', created_at: 0, auth: 'session' }),
    );
    expect(await result).toBe(true);
    expect(await run()).toBe(true);
    ctrl.expectNone('/api/v1/auth/me');
  });
});
