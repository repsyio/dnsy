import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { apiInterceptor } from '../../core/api.interceptor';
import { LoginPage } from './login.page';

describe('LoginPage', () => {
  let ctrl: HttpTestingController;
  let router: Router;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withInterceptors([apiInterceptor])),
        provideHttpClientTesting(),
      ],
    });
    ctrl = TestBed.inject(HttpTestingController);
    router = TestBed.inject(Router);
  });

  async function submit(user: string, pass: string) {
    const fixture = TestBed.createComponent(LoginPage);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const set = async (id: string, v: string) => {
      const input = el.querySelector<HTMLInputElement>('#' + id)!;
      input.value = v;
      input.dispatchEvent(new Event('input'));
      await fixture.whenStable();
    };
    await set('username', user);
    await set('password', pass);
    el.querySelector('form')!.dispatchEvent(new Event('submit'));
    return { fixture, el };
  }

  it('signs in and navigates to the dashboard', async () => {
    const nav = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    await submit('root', 'pw');
    await vi.waitFor(() => ctrl.expectOne('/api/v1/auth/login').flush({}));
    await vi.waitFor(() =>
      ctrl
        .expectOne('/api/v1/auth/me')
        .flush({ id: 1, username: 'root', role: 'admin', created_at: 0, auth: 'session' }),
    );
    await vi.waitFor(() => expect(nav).toHaveBeenCalledWith('/dashboard'));
  });

  it('shows the problem detail on failure', async () => {
    const { fixture, el } = await submit('root', 'bad');
    await vi.waitFor(() =>
      ctrl.expectOne('/api/v1/auth/login').flush(
        {
          type: 'https://dnsy.dev/problems/unauthorized',
          title: 'Unauthorized',
          status: 401,
          detail: 'invalid credentials',
        },
        { status: 401, statusText: 'Unauthorized' },
      ),
    );
    await vi.waitFor(async () => {
      await fixture.whenStable();
      expect(el.querySelector('[role=alert]')?.textContent).toContain('invalid credentials');
    });
  });
});
