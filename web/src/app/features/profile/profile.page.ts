import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormControl, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { ApiError } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import { AuthService } from '../../core/auth.service';
import { MascotLoadingComponent } from '../../shared/mascot';
import { formatEpoch, messageOf } from '../../shared/util/util';
import { MIN_PASSWORD, passwordStrength } from '../../shared/util/password-strength';

/** Current user, password change, session info and sign out. */
@Component({
  selector: 'app-profile-page',
  imports: [MascotLoadingComponent, ReactiveFormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1 class="mb-6 page-title">Profile</h1>
    @if (auth.user(); as u) {
      <section class="panel mb-6" aria-labelledby="pa-h">
        <h2 id="pa-h" class="mb-4 section-title">Account</h2>
        <dl class="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div>
            <dt class="text-xs uppercase tracking-wider text-muted">Username</dt>
            <dd class="break-all">{{ u.username }}</dd>
          </div>
          <div>
            <dt class="text-xs uppercase tracking-wider text-muted">Role</dt>
            <dd>{{ u.role }}</dd>
          </div>
          <div>
            <dt class="text-xs uppercase tracking-wider text-muted">Created</dt>
            <dd>{{ fmt(u.created_at) }}</dd>
          </div>
          <div>
            <dt class="text-xs uppercase tracking-wider text-muted">Signed in with</dt>
            <dd>{{ u.auth }}</dd>
          </div>
        </dl>
      </section>

      <section class="panel mb-6" aria-labelledby="pp-h">
        <h2 id="pp-h" class="mb-4 section-title">Change password</h2>
        <form class="max-w-md" novalidate (submit)="change($event)">
          <label class="field-label" for="pp-cur">Current password</label>
          <input
            id="pp-cur"
            class="field-input mb-4"
            type="password"
            autocomplete="current-password"
            [value]="current()"
            (input)="current.set(val($event))"
          />
          <label class="field-label" for="pp-new">New password</label>
          <input
            id="pp-new"
            class="field-input"
            type="password"
            autocomplete="new-password"
            aria-describedby="pp-hints"
            [formControl]="nextCtl"
          />
          @if (nextCtl.invalid && nextCtl.dirty) {
            <p class="field-error mt-1" role="alert">
              The new password needs at least {{ minPassword }} characters.
            </p>
          }
          <div id="pp-hints" class="mb-4 mt-1 text-xs text-muted" aria-live="polite">
            <p>Strength: {{ strength().label }}</p>
            @for (h of strength().hints; track h) {
              <p>{{ h }}</p>
            }
          </div>
          <label class="field-label" for="pp-conf">Confirm new password</label>
          <input
            id="pp-conf"
            class="field-input mb-4"
            type="password"
            autocomplete="new-password"
            [value]="confirm()"
            (input)="confirm.set(val($event))"
          />
          @if (error(); as e) {
            <p class="field-error mb-3" role="alert">{{ e }}</p>
          }
          @if (done()) {
            <p class="mb-3 text-sm text-secure" role="status">
              Password changed. Your other sessions were ended.
            </p>
          }
          <button class="btn" type="submit" [disabled]="busy()">Change password</button>
        </form>
      </section>

      <section class="panel" aria-labelledby="ps-h">
        <h2 id="ps-h" class="mb-2 section-title">Session</h2>
        <p class="mb-4 text-sm text-muted">
          A session ends after 30 minutes without use or 12 hours after sign in. Changing your
          password or role ends all sessions.
        </p>
        <button class="btn btn-danger" type="button" (click)="logout()">Sign out</button>
      </section>
    } @else {
      <dnsy-mascot-loading message="Loading profile..." />
    }
  `,
})
export class ProfilePage {
  protected readonly auth = inject(AuthService);
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);

  protected readonly current = signal('');
  protected readonly minPassword = MIN_PASSWORD;
  protected readonly nextCtl = new FormControl('', {
    nonNullable: true,
    validators: [Validators.required, Validators.minLength(MIN_PASSWORD)],
  });
  protected readonly next = toSignal(this.nextCtl.valueChanges, { initialValue: '' });
  protected readonly confirm = signal('');
  protected readonly error = signal<string | null>(null);
  protected readonly done = signal(false);
  protected readonly busy = signal(false);
  protected readonly strength = computed(() => passwordStrength(this.next()));
  protected readonly fmt = formatEpoch;

  protected val(e: Event): string {
    return (e.target as HTMLInputElement).value;
  }

  protected async change(event: Event): Promise<void> {
    event.preventDefault();
    this.done.set(false);
    if (!this.current()) return this.error.set('Enter your current password.');
    if (this.nextCtl.invalid) return this.nextCtl.markAsDirty();
    if (this.next() !== this.confirm()) return this.error.set('The passwords do not match.');
    this.error.set(null);
    this.busy.set(true);
    try {
      await firstValueFrom(
        this.api.put('/auth/me/password', {
          current_password: this.current(),
          new_password: this.next(),
        }),
      );
      this.current.set('');
      this.nextCtl.reset();
      this.confirm.set('');
      this.done.set(true);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401 && !(await this.auth.refresh())) {
        await this.router.navigate(['/login']);
        return;
      }
      this.error.set(messageOf(e, 'Could not change the password.'));
    } finally {
      this.busy.set(false);
    }
  }

  protected async logout(): Promise<void> {
    try {
      await this.auth.logout();
    } finally {
      await this.router.navigate(['/login']);
    }
  }
}
