import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { apiInterceptor } from '../../core/api.interceptor';
import { LoginPage } from './login.page';
import { LOGIN_SCENE_FACTORY } from './scene-factory';

describe('LoginPage', () => {
  let ctrl: HttpTestingController;
  let router: Router;
  const dispose = vi.fn();
  const create = vi.fn(() => ({ dispose }));

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    dispose.mockClear();
    create.mockClear();
  });

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withInterceptors([apiInterceptor])),
        provideHttpClientTesting(),
        { provide: LOGIN_SCENE_FACTORY, useValue: create },
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

  it('shows a non-enumerating message for a 401', async () => {
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
      expect(el.querySelector('[role=alert]')?.textContent).toContain(
        'Invalid username or password',
      );
    });
  });

  it('shows a distinct message for a 503', async () => {
    const { fixture, el } = await submit('root', 'pw');
    await vi.waitFor(() =>
      ctrl.expectOne('/api/v1/auth/login').flush(
        {
          type: 'https://dnsy.dev/problems/unavailable',
          title: 'Service Unavailable',
          status: 503,
          detail: 'too many password checks in flight',
        },
        { status: 503, statusText: 'Service Unavailable' },
      ),
    );
    await vi.waitFor(async () => {
      await fixture.whenStable();
      expect(el.querySelector('[role=alert]')?.textContent).toContain('server is busy');
    });
  });

  it('setup_form_is_invalid_with_a_short_password', async () => {
    const fixture = TestBed.createComponent(LoginPage);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    el.querySelectorAll<HTMLButtonElement>('button').forEach((b) => {
      if (b.textContent?.includes('First run')) b.click();
    });
    await fixture.whenStable();
    const set = async (id: string, v: string) => {
      const input = el.querySelector<HTMLInputElement>('#' + id)!;
      input.value = v;
      input.dispatchEvent(new Event('input'));
      await fixture.whenStable();
    };
    await set('code', 'abc');
    await set('username', 'root');
    await set('password', 'short');
    const submitBtn = el.querySelector<HTMLButtonElement>('button[type=submit]')!;
    expect(submitBtn.disabled).toBe(true);
    el.querySelector('form')!.dispatchEvent(new Event('submit'));
    ctrl.expectNone('/api/v1/auth/bootstrap');
    await set('password', 'long-enough');
    expect(submitBtn.disabled).toBe(false);
  });

  it('starts the scene after render, decorative and animated without reduced motion', async () => {
    const fixture = TestBed.createComponent(LoginPage);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const canvas = el.querySelector('canvas')!;
    expect(create).toHaveBeenCalledTimes(1);
    expect(create).toHaveBeenCalledWith(canvas, { reducedMotion: false });
    expect(el.querySelector('[data-testid=login-art]')?.getAttribute('aria-hidden')).toBe('true');
    expect(el.querySelector('form')).not.toBeNull();
  });

  it('reduced_motion_asks_for_a_still_scene', async () => {
    vi.stubGlobal('matchMedia', () => ({
      matches: true,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    }));
    const fixture = TestBed.createComponent(LoginPage);
    await fixture.whenStable();
    expect(create).toHaveBeenCalledWith(expect.any(HTMLCanvasElement), { reducedMotion: true });
  });

  it('restarts the scene when the reduced-motion preference changes', async () => {
    let listener: ((e: { matches: boolean }) => void) | undefined;
    vi.stubGlobal('matchMedia', () => ({
      matches: false,
      addEventListener: (_: string, fn: typeof listener) => (listener = fn),
      removeEventListener: () => undefined,
    }));
    const fixture = TestBed.createComponent(LoginPage);
    await fixture.whenStable();
    listener!({ matches: true });
    await fixture.whenStable();
    expect(dispose).toHaveBeenCalledTimes(1);
    expect(create).toHaveBeenLastCalledWith(expect.any(HTMLCanvasElement), {
      reducedMotion: true,
    });
  });

  it('scene_disposed_on_destroy', async () => {
    const fixture = TestBed.createComponent(LoginPage);
    await fixture.whenStable();
    expect(create).toHaveBeenCalled();
    fixture.destroy();
    expect(dispose).toHaveBeenCalledTimes(1);
  });

  it('locks the form with a countdown on 429', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    try {
      const { fixture, el } = await submit('root', 'pw');
      await vi.waitFor(() =>
        ctrl.expectOne('/api/v1/auth/login').flush(
          {
            type: 'https://dnsy.dev/problems/throttled',
            title: 'Too Many Requests',
            status: 429,
            detail: 'too many failed logins',
            retry_after_secs: 2,
          },
          { status: 429, statusText: 'Too Many Requests' },
        ),
      );
      await vi.waitFor(async () => {
        await fixture.whenStable();
        expect(el.querySelector('[role=status]')?.textContent).toContain('2s');
      });
      expect(el.querySelector<HTMLButtonElement>('button[type=submit]')!.disabled).toBe(true);
      vi.advanceTimersByTime(2000);
      await fixture.whenStable();
      expect(el.querySelector('[role=status]')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('creates the first admin with the setup code, then signs in', async () => {
    const nav = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    const fixture = TestBed.createComponent(LoginPage);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    el.querySelector<HTMLButtonElement>('button[type=button]')!.click();
    await fixture.whenStable();
    const set = async (id: string, v: string) => {
      const input = el.querySelector<HTMLInputElement>('#' + id)!;
      input.value = v;
      input.dispatchEvent(new Event('input'));
      await fixture.whenStable();
    };
    await set('code', 'abc');
    await set('username', 'root');
    await set('password', 'longenough');
    el.querySelector('form')!.dispatchEvent(new Event('submit'));
    const req = await vi.waitFor(() => ctrl.expectOne('/api/v1/auth/bootstrap'));
    expect(req.request.body).toEqual({ code: 'abc', username: 'root', password: 'longenough' });
    req.flush({});
    await vi.waitFor(() => ctrl.expectOne('/api/v1/auth/login').flush({}));
    await vi.waitFor(() =>
      ctrl
        .expectOne('/api/v1/auth/me')
        .flush({ id: 1, username: 'root', role: 'admin', created_at: 0, auth: 'session' }),
    );
    await vi.waitFor(() => expect(nav).toHaveBeenCalledWith('/dashboard'));
  });
});
