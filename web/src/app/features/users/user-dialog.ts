import { ChangeDetectionStrategy, Component, computed, input, output, signal } from '@angular/core';
import { Dialog } from '../zones/dialog';
import { MIN_PASSWORD, passwordStrength } from '../profile/password-strength';
import { ROLES } from './users.service';

export type UserDialogMode = 'create' | 'role' | 'password';
export interface UserFormValue {
  username: string;
  password: string;
  role: string;
}

/** One form for the three user edits: create, change role, reset password. */
@Component({
  selector: 'app-user-dialog',
  imports: [Dialog],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <app-dialog [heading]="heading()" (closed)="cancelled.emit()">
      <form novalidate (submit)="submit($event)">
        @if (mode() === 'create') {
          <label class="field-label" for="ud-name">Username</label>
          <input
            id="ud-name"
            class="field-input mb-4"
            autocomplete="off"
            [value]="username()"
            (input)="username.set(val($event))"
          />
        }
        @if (mode() !== 'role') {
          <label class="field-label" for="ud-pw">
            {{ mode() === 'create' ? 'Password' : 'New password' }}
          </label>
          <input
            id="ud-pw"
            class="field-input"
            type="password"
            autocomplete="new-password"
            aria-describedby="ud-strength"
            [value]="password()"
            (input)="password.set(val($event))"
          />
          <p id="ud-strength" class="mb-4 mt-1 text-xs text-muted" aria-live="polite">
            Strength: {{ strength().label }}
            @if (strength().hints.length > 0) {
              . {{ strength().hints[0] }}
            }
          </p>
        }
        @if (mode() !== 'password') {
          <label class="field-label" for="ud-role">Role</label>
          <select
            id="ud-role"
            class="field-input mb-4"
            [value]="role()"
            (change)="role.set(val($event))"
          >
            @for (r of roles; track r) {
              <option [value]="r" [selected]="r === role()">{{ r }}</option>
            }
          </select>
        }
        @if (mode() === 'role') {
          <p class="mb-4 text-xs text-muted">Changing the role signs the user out everywhere.</p>
        }
        @if (mode() === 'password') {
          <p class="mb-4 text-xs text-muted">
            Resetting the password signs the user out everywhere.
          </p>
        }
        @if (localError() || error()) {
          <p class="field-error" role="alert">{{ localError() ?? error() }}</p>
        }
        <div class="mt-6 flex flex-wrap justify-end gap-3">
          <button class="btn" type="button" (click)="cancelled.emit()">Cancel</button>
          <button class="btn" type="submit" [disabled]="busy()">{{ submitLabel() }}</button>
        </div>
      </form>
    </app-dialog>
  `,
})
export class UserDialog {
  readonly mode = input.required<UserDialogMode>();
  readonly initialRole = input('viewer');
  readonly target = input<string>();
  readonly busy = input(false);
  readonly error = input<string | null>(null);
  readonly saved = output<UserFormValue>();
  readonly cancelled = output<void>();

  protected readonly roles = ROLES;
  protected readonly username = signal('');
  protected readonly password = signal('');
  protected readonly role = signal<string | null>(null);
  protected readonly localError = signal<string | null>(null);
  protected readonly strength = computed(() => passwordStrength(this.password()));
  protected readonly heading = computed(() => {
    switch (this.mode()) {
      case 'create':
        return 'Create user';
      case 'role':
        return `Change role of ${this.target()}`;
      default:
        return `Reset password of ${this.target()}`;
    }
  });
  protected readonly submitLabel = computed(() =>
    this.mode() === 'create' ? 'Create' : this.mode() === 'role' ? 'Save role' : 'Reset password',
  );

  protected val(e: Event): string {
    return (e.target as HTMLInputElement).value;
  }

  protected submit(event: Event): void {
    event.preventDefault();
    const mode = this.mode();
    const username = this.username().trim();
    if (mode === 'create' && !username) {
      this.localError.set('Enter a username.');
      return;
    }
    if (mode !== 'role' && this.password().length < MIN_PASSWORD) {
      this.localError.set(`The password needs at least ${MIN_PASSWORD} characters.`);
      return;
    }
    this.localError.set(null);
    this.saved.emit({
      username,
      password: this.password(),
      role: this.role() ?? this.initialRole(),
    });
  }
}
