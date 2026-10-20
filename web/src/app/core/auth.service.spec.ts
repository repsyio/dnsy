import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { apiInterceptor } from './api.interceptor';
import { TestBed } from '@angular/core/testing';
import { ApiError } from './api-error';
import { AuthService } from './auth.service';

const ME = { id: '1', username: 'root', role: 'admin' };

describe('AuthService', () => {
  let auth: AuthService;
  let ctrl: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([apiInterceptor])),
        provideHttpClientTesting(),
      ],
    });
    auth = TestBed.inject(AuthService);
    ctrl = TestBed.inject(HttpTestingController);
  });

  it('login posts credentials then loads the user; logout clears it', async () => {
    const p = auth.login('root', 'pw');
    await vi.waitFor(() => {
      const r = ctrl.expectOne('/api/v1/auth/login');
      expect(r.request.body).toEqual({ username: 'root', password: 'pw' });
      r.flush({});
    });
    await vi.waitFor(() => ctrl.expectOne('/api/v1/auth/me').flush(ME));
    await p;
    expect(auth.authenticated()).toBe(true);
    expect(auth.user()?.username).toBe('root');

    const out = auth.logout();
    await vi.waitFor(() => ctrl.expectOne('/api/v1/auth/logout').flush({}));
    await out;
    expect(auth.authenticated()).toBe(false);
  });

  it('refresh rethrows non-401 errors', async () => {
    const p = auth.refresh();
    const assertion = expect(p).rejects.toBeInstanceOf(ApiError);
    await vi.waitFor(() =>
      ctrl.expectOne('/api/v1/auth/me').flush('x', { status: 500, statusText: 'x' }),
    );
    await assertion;
  });
});
