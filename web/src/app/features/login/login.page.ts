import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  afterNextRender,
  computed,
  effect,
  inject,
  signal,
  viewChild,
  ElementRef,
  DOCUMENT,
} from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { ApiError } from '../../core/api-error';
import { AuthService } from '../../core/auth.service';
import { MascotLoadingComponent } from '../../shared/mascot';
import { MIN_PASSWORD } from '../../shared/util/password-strength';
import { injectReducedMotion } from '../../shared/mascot/reduced-motion';
import type { LoginScene } from './login-scene';
import { LOGIN_SCENE_LOADER } from './scene-loader';
import { decideScene, detectWebGl, fallbackGrid, retrySeconds } from './scene-support';

const INPUT =
  'mb-4 w-full rounded-sm border border-cyan/40 bg-bg px-3 py-2 text-text placeholder:text-muted';
const LABEL = 'mb-1 block text-xs uppercase text-muted';

/** Sign-in and first-admin setup over a three.js light-grid scene (static SVG grid as fallback). */
@Component({
  selector: 'app-login-page',
  imports: [ReactiveFormsModule, MascotLoadingComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <canvas
      #scene
      aria-hidden="true"
      class="fixed inset-0 -z-10 h-full w-full"
      [class.hidden]="mode() !== 'webgl'"
    ></canvas>
    @if (mode() === 'static') {
      <svg
        class="fixed inset-0 -z-10 h-full w-full"
        viewBox="0 0 100 100"
        preserveAspectRatio="xMidYMid slice"
        aria-hidden="true"
        data-testid="static-grid"
      >
        <circle cx="50" cy="50" r="14" class="fill-orange/20" />
        <g class="stroke-cyan/50" stroke-width="0.15" fill="none">
          @for (x of grid.fan; track x) {
            <line x1="50" y1="50" [attr.x2]="x" y2="100" vector-effect="non-scaling-stroke" />
          }
          @for (y of grid.rows; track y) {
            <line x1="0" x2="100" [attr.y1]="y" [attr.y2]="y" vector-effect="non-scaling-stroke" />
          }
        </g>
        <line x1="0" y1="50" x2="100" y2="50" class="stroke-cyan/70" stroke-width="0.12" />
      </svg>
    }
    <main class="grid min-h-screen place-items-center p-4">
      <form
        class="panel w-full max-w-sm"
        [formGroup]="form"
        (ngSubmit)="submit()"
        [attr.aria-busy]="busy()"
      >
        <img src="mark.svg" alt="" class="mx-auto h-16 w-16" />
        <h1 class="my-4 text-center text-2xl font-bold text-cyan">DNSY</h1>
        @if (setup()) {
          <p class="mb-4 text-sm text-muted">
            First run: enter the one-time code printed in the server's log, then choose the admin
            account.
          </p>
          <label [class]="label" for="code">Setup code</label>
          <input
            id="code"
            name="code"
            [class]="input"
            autocomplete="one-time-code"
            autocapitalize="off"
            spellcheck="false"
            formControlName="code"
          />
        }
        <label [class]="label" for="username">Username</label>
        <input
          id="username"
          name="username"
          [class]="input"
          autocomplete="username"
          autocapitalize="off"
          formControlName="username"
        />
        <label [class]="label" for="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          [class]="input"
          [attr.autocomplete]="setup() ? 'new-password' : 'current-password'"
          formControlName="password"
        />
        @if (setup()) {
          <p
            class="-mt-2 mb-4 text-xs"
            [class.text-orange]="
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
          <p class="mb-4 text-sm text-orange" role="alert">{{ error() }}</p>
        }
        @if (cooldown() > 0) {
          <p class="mb-4 text-sm text-orange" role="status">
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
          class="btn w-full"
          type="submit"
          [disabled]="busy() || cooldown() > 0 || form.invalid"
        >
          {{ setup() ? 'Create admin' : 'Sign in' }}
        </button>
        <button
          type="button"
          class="mt-4 w-full cursor-pointer bg-transparent text-xs text-cyan underline"
          [disabled]="busy()"
          (click)="toggleSetup()"
        >
          {{ setup() ? 'Back to sign in' : 'First run? Set up the admin account' }}
        </button>
      </form>
    </main>
  `,
})
export class LoginPage {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly doc = inject(DOCUMENT);
  private readonly loadScene = inject(LOGIN_SCENE_LOADER);
  private readonly reduced = injectReducedMotion();
  private readonly canvas = viewChild.required<ElementRef<HTMLCanvasElement>>('scene');
  private readonly webgl = signal(false);
  private scene: LoginScene | null = null;
  private timer: ReturnType<typeof setInterval> | undefined;
  private destroyed = false;

  protected readonly input = INPUT;
  protected readonly label = LABEL;
  protected readonly grid = fallbackGrid();
  protected readonly mode = computed(() => decideScene(this.reduced(), this.webgl()));
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
    const destroyRef = inject(DestroyRef);
    destroyRef.onDestroy(() => {
      this.destroyed = true;
      clearInterval(this.timer);
      this.stopScene();
    });
    afterNextRender(() => this.webgl.set(detectWebGl(this.doc)));
    effect(() => {
      if (this.mode() === 'webgl') void this.startScene();
      else this.stopScene();
    });
  }

  private async startScene(): Promise<void> {
    try {
      const create = await this.loadScene();
      if (this.destroyed || this.mode() !== 'webgl' || this.scene) return;
      this.scene = create(this.canvas().nativeElement);
    } catch {
      this.webgl.set(false); // chunk or context failure: use the static grid
    }
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
