import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  afterNextRender,
  effect,
  inject,
  signal,
  viewChild,
  ElementRef,
} from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { ApiError } from '../../core/api-error';
import { AuthService } from '../../core/auth.service';
import { MascotLoadingComponent } from '../../shared/mascot';
import { MIN_PASSWORD } from '../../shared/util/password-strength';
import { injectReducedMotion } from '../../shared/mascot/reduced-motion';
import type { LoginScene } from './login-scene';
import { LOGIN_SCENE_FACTORY } from './scene-factory';
import { retrySeconds } from './scene-support';

/**
 * Sign-in and first-admin setup. Two columns from `md` up: the form on the left, the blob canvas on
 * the right behind a hairline divider. On phones the canvas fills the background at half opacity
 * and the form sits on a solid surface panel.
 */
@Component({
  selector: 'app-login-page',
  imports: [ReactiveFormsModule, MascotLoadingComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="min-h-screen md:grid md:grid-cols-[380px_1fr]">
      <main
        class="relative flex min-h-screen items-center justify-center p-4 md:block md:border-r-[0.5px] md:border-line md:p-0"
      >
        <form
          class="flex w-full max-w-sm flex-col rounded-sm border-line bg-surface p-6 hairline md:min-h-screen md:max-w-none md:justify-center md:rounded-none md:border-0 md:bg-transparent md:px-11 md:py-14"
          [formGroup]="form"
          (ngSubmit)="submit()"
          [attr.aria-busy]="busy()"
        >
          <div class="mb-4 flex items-center gap-3">
            <img src="mark.svg" alt="" class="h-9 w-9" />
            <h1 class="wordmark text-lg">DNSY</h1>
          </div>
          @if (setup()) {
            <p class="mb-6 text-sm leading-relaxed text-muted">
              First run: enter the one-time code printed in the server's log, then choose the admin
              account.
            </p>
            <label class="field-label" for="code">Setup code</label>
            <input
              id="code"
              name="code"
              class="field-input mb-4"
              autocomplete="one-time-code"
              autocapitalize="off"
              spellcheck="false"
              formControlName="code"
            />
          } @else {
            <p class="mb-6 text-sm leading-relaxed text-muted">
              Sign in to manage zones, filtering and DNSSEC on this node.
            </p>
          }
          <label class="field-label" for="username">Username</label>
          <input
            id="username"
            name="username"
            class="field-input mb-4"
            autocomplete="username"
            autocapitalize="off"
            formControlName="username"
          />
          <label class="field-label" for="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            class="field-input mb-4"
            [attr.autocomplete]="setup() ? 'new-password' : 'current-password'"
            formControlName="password"
          />
          @if (setup()) {
            <p
              class="-mt-2 mb-4 text-xs"
              [class.text-amber]="
                form.controls.password.errors?.['minlength'] && form.controls.password.dirty
              "
              [class.text-muted]="
                !(form.controls.password.errors?.['minlength'] && form.controls.password.dirty)
              "
              id="password-hint"
            >
              At least {{ minPassword }} characters.
            </p>
          }
          @if (error()) {
            <p class="mb-4 text-sm text-amber" role="alert">{{ error() }}</p>
          }
          @if (cooldown() > 0) {
            <p class="mb-4 text-sm text-amber" role="status">
              Too many attempts. Try again in {{ cooldown() }}s.
            </p>
          }
          @if (busy()) {
            <dnsy-mascot-loading
              size="sm"
              [message]="setup() ? 'Creating account...' : 'Signing in...'"
            />
          }
          <button
            class="btn mt-2 w-full py-3"
            type="submit"
            [disabled]="busy() || cooldown() > 0 || form.invalid"
          >
            {{ setup() ? 'Create admin' : 'Sign in' }}
          </button>
          <button
            type="button"
            class="mt-4 w-full cursor-pointer bg-transparent text-xs text-muted underline-offset-4 hover:text-text hover:underline"
            [disabled]="busy()"
            (click)="toggleSetup()"
          >
            {{ setup() ? 'Back to sign in' : 'First run? Set up the admin account' }}
          </button>
        </form>
      </main>
      <div
        class="fixed inset-0 -z-10 opacity-50 md:sticky md:top-0 md:z-auto md:h-screen md:opacity-100"
        aria-hidden="true"
        data-testid="login-art"
      >
        <canvas #scene class="block h-full w-full"></canvas>
      </div>
    </div>
  `,
})
export class LoginPage {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly createScene = inject(LOGIN_SCENE_FACTORY);
  private readonly reduced = injectReducedMotion();
  private readonly canvas = viewChild.required<ElementRef<HTMLCanvasElement>>('scene');
  private scene: LoginScene | null = null;
  private rendered = false;
  private timer: ReturnType<typeof setInterval> | undefined;

  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly cooldown = signal(0);
  protected readonly setup = signal(false);
  protected readonly minPassword = MIN_PASSWORD;
  protected readonly form = new FormGroup({
    code: new FormControl('', { nonNullable: true }),
    username: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    password: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  });

  constructor() {
    inject(DestroyRef).onDestroy(() => {
      clearInterval(this.timer);
      this.stopScene();
    });
    afterNextRender(() => {
      this.rendered = true;
      this.startScene(this.reduced());
    });
    // A live change of the reduced-motion preference restarts the scene in the matching mode.
    effect(() => {
      const reduced = this.reduced();
      if (this.rendered) this.startScene(reduced);
    });
  }

  private startScene(reducedMotion: boolean): void {
    this.stopScene();
    this.scene = this.createScene(this.canvas().nativeElement, { reducedMotion });
  }

  private stopScene(): void {
    this.scene?.dispose();
    this.scene = null;
  }

  protected toggleSetup(): void {
    this.setup.update((v) => !v);
    this.error.set(null);
    this.applySetupValidators();
  }

  private applySetupValidators(): void {
    const { code, password } = this.form.controls;
    const setup = this.setup();
    code.setValidators(setup ? [Validators.required] : []);
    password.setValidators(
      setup ? [Validators.required, Validators.minLength(MIN_PASSWORD)] : [Validators.required],
    );
    code.updateValueAndValidity();
    password.updateValueAndValidity();
  }

  protected async submit(): Promise<void> {
    if (this.form.invalid) return;
    const { code, username, password } = this.form.getRawValue();
    this.busy.set(true);
    this.error.set(null);
    try {
      if (this.setup()) {
        await this.auth.bootstrap(code, username, password);
      } else {
        await this.auth.login(username, password);
      }
      const redirect = this.route.snapshot.queryParamMap.get('redirect');
      await this.router.navigateByUrl(
        redirect?.startsWith('/') && !redirect.startsWith('//') ? redirect : '/dashboard',
      );
    } catch (e) {
      this.fail(e);
    } finally {
      this.busy.set(false);
    }
  }

  private fail(e: unknown): void {
    if (e instanceof ApiError && e.status === 429) {
      this.startCooldown(retrySeconds(e.problem?.retry_after_secs));
    } else if (e instanceof ApiError && e.status === 409 && this.setup()) {
      this.setup.set(false);
      this.applySetupValidators();
      this.error.set('An admin already exists. Sign in instead.');
    } else if (e instanceof ApiError && e.status === 401) {
      this.error.set('Invalid username or password');
    } else if (e instanceof ApiError && e.status === 503) {
      this.error.set('The server is busy. Try again in a moment.');
    } else {
      this.error.set(e instanceof ApiError ? e.message : 'Sign-in failed');
    }
  }

  private startCooldown(seconds: number): void {
    clearInterval(this.timer);
    this.cooldown.set(seconds);
    this.timer = setInterval(() => {
      this.cooldown.update((s) => s - 1);
      if (this.cooldown() <= 0) clearInterval(this.timer);
    }, 1000);
  }
}
