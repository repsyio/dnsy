import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { ApiError } from './api-error';
import { apiInterceptor } from './api.interceptor';
import { AuthService } from './auth.service';

describe('apiInterceptor', () => {
  let http: HttpClient;
  let ctrl: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withInterceptors([apiInterceptor])),
        provideHttpClientTesting(),
      ],
    });
    http = TestBed.inject(HttpClient);
    ctrl = TestBed.inject(HttpTestingController);
    document.cookie = 'dnsy_csrf=tok%20en; path=/';
  });

  afterEach(() => {
    document.cookie = 'dnsy_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
    ctrl.verify();
  });

  it('csrf_interceptor_adds_header', () => {
    http.post('/api/v1/zones', {}).subscribe();
    const req = ctrl.expectOne('/api/v1/zones');
    expect(req.request.headers.get('X-CSRF-Token')).toBe('tok en');
    req.flush({});
  });

  it('csrf_header_not_added_on_safe_or_foreign_requests', () => {
    http.get('/api/v1/version').subscribe();
    expect(ctrl.expectOne('/api/v1/version').request.headers.has('X-CSRF-Token')).toBe(false);
    http.post('https://example.com/x', {}).subscribe();
    const foreign = ctrl.expectOne('https://example.com/x');
    expect(foreign.request.headers.has('X-CSRF-Token')).toBe(false);
  });

  it('problem_json_mapped_to_error', () => {
    let err: unknown;
    http.get('/api/v1/zones').subscribe({ error: (e) => (err = e) });
    const problem = {
      type: 'https://dnsy.dev/problems/not-found',
      title: 'Not found',
      status: 404,
      detail: 'no such zone',
    };
    ctrl.expectOne('/api/v1/zones').flush(problem, { status: 404, statusText: 'Not Found' });
    expect(err).toBeInstanceOf(ApiError);
    const e = err as ApiError;
    expect(e.status).toBe(404);
    expect(e.kind).toBe('not-found');
    expect(e.message).toBe('no such zone');
    expect(e.problem).toEqual(problem);
  });

  it('non_problem_error_has_no_problem', () => {
    let err: unknown;
    http.get('/api/v1/x').subscribe({ error: (e) => (err = e) });
    ctrl.expectOne('/api/v1/x').flush('boom', { status: 502, statusText: 'Bad Gateway' });
    const e = err as ApiError;
    expect(e.problem).toBeNull();
    expect(e.kind).toBe('unknown');
    expect(e.status).toBe(502);
  });

  it('unauthorized_clears_session_and_goes_to_login', () => {
    const router = TestBed.inject(Router);
    const nav = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    const signedOut = vi.spyOn(TestBed.inject(AuthService), 'markSignedOut');
    http.get('/api/v1/zones').subscribe({ error: () => undefined });
    ctrl.expectOne('/api/v1/zones').flush(null, { status: 401, statusText: 'Unauthorized' });
    expect(signedOut).toHaveBeenCalled();
    expect(nav).toHaveBeenCalledWith(['/login']);
  });

  it('password_change_401_does_not_sign_out', () => {
    const signedOut = vi.spyOn(TestBed.inject(AuthService), 'markSignedOut');
    http.put('/api/v1/auth/me/password', {}).subscribe({ error: () => undefined });
    ctrl
      .expectOne('/api/v1/auth/me/password')
      .flush(null, { status: 401, statusText: 'Unauthorized' });
    expect(signedOut).not.toHaveBeenCalled();
  });
});
