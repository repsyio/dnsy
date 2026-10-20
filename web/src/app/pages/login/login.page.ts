import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { ApiError } from '../../core/api-error';
import { AuthService } from '../../core/auth.service';

/** Plain sign-in form. The three.js scene arrives with DNSY-46. */
@Component({
  selector: 'app-login-page',
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <main class="grid min-h-screen place-items-center p-4">
      <form class="panel w-full max-w-sm" (ngSubmit)="submit()" #f="ngForm">
        <img src="mark.svg" alt="" class="mx-auto h-20 w-20" />
        <h1 class="my-4 text-center text-2xl font-bold text-cyan">DNSY</h1>
        <label class="mb-1 block text-xs uppercase text-muted" for="username">Username</label>
        <input
          id="username"
          name="username"
          class="mb-4 w-full rounded-sm border border-cyan/40 bg-bg px-3 py-2 text-text"
          autocomplete="username"
          required
          [(ngModel)]="username"
        />
        <label class="mb-1 block text-xs uppercase text-muted" for="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          class="mb-4 w-full rounded-sm border border-cyan/40 bg-bg px-3 py-2 text-text"
          autocomplete="current-password"
          required
          [(ngModel)]="password"
        />
        @if (error()) {
          <p class="mb-4 text-sm text-bogus" role="alert">{{ error() }}</p>
        }
        <button class="btn w-full" type="submit" [disabled]="busy() || f.invalid">Sign in</button>
      </form>
    </main>
  `,
})
export class LoginPage {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  protected username = '';
  protected password = '';
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  protected async submit(): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    try {
      await this.auth.login(this.username, this.password);
      const redirect = this.route.snapshot.queryParamMap.get('redirect');
      await this.router.navigateByUrl(redirect?.startsWith('/') ? redirect : '/dashboard');
    } catch (e) {
      this.error.set(e instanceof ApiError ? e.message : 'Sign-in failed');
    } finally {
      this.busy.set(false);
    }
  }
}
