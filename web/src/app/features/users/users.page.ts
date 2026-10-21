import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { AuthService } from '../../core/auth.service';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
} from '../../shared/mascot';
import { formatEpoch, messageOf } from '../admin-shared/util';
import { ConfirmDialog } from '../zones/confirm-dialog';
import { UserDialog, UserDialogMode, UserFormValue } from './user-dialog';
import { UserInfo, UsersService } from './users.service';

/** User administration: list, create, change role, reset password, delete. */
@Component({
  selector: 'app-users-page',
  imports: [
    ConfirmDialog,
    MascotEmptyComponent,
    MascotErrorComponent,
    MascotLoadingComponent,
    UserDialog,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="mb-6 flex flex-wrap items-center justify-between gap-3">
      <h1 class="text-2xl font-bold text-cyan">Users</h1>
      <button class="btn" type="button" (click)="open('create')">Create user</button>
    </div>
    @if (notice(); as n) {
      <p class="mb-4 text-sm text-secure" role="status">{{ n }}</p>
    }
    <section class="panel" aria-labelledby="u-h">
      <h2 id="u-h" class="sr-only">Accounts</h2>
      @switch (status()) {
        @case ('loading') {
          <div aria-busy="true"><dnsy-mascot-loading message="Loading users..." /></div>
        }
        @case ('error') {
          <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="load()" />
        }
        @default {
          @if (users().length === 0) {
            <dnsy-mascot-empty message="No users yet." />
          } @else {
            <div class="overflow-x-auto">
              <table class="w-full text-left text-sm">
                <caption class="sr-only">
                  Users
                </caption>
                <thead class="text-xs uppercase tracking-wider text-muted">
                  <tr>
                    <th scope="col" class="py-2 pr-4">Username</th>
                    <th scope="col" class="py-2 pr-4">Role</th>
                    <th scope="col" class="py-2 pr-4">Created</th>
                    <th scope="col" class="py-2"><span class="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  @for (u of users(); track u.id) {
                    <tr class="border-t border-cyan/20">
                      <td class="py-2 pr-4 break-all">
                        {{ u.username }}
                        @if (isSelf(u)) {
                          <span class="text-xs text-muted">(you)</span>
                        }
                      </td>
                      <td class="py-2 pr-4">
                        <span class="badge badge-ok">{{ u.role }}</span>
                        @if (u.disabled) {
                          <span class="badge badge-warn ml-2">disabled</span>
                        }
                      </td>
                      <td class="py-2 pr-4 whitespace-nowrap">{{ fmt(u.created_at) }}</td>
                      <td class="py-2">
                        <div class="flex flex-wrap gap-2">
                          <button
                            class="btn"
                            type="button"
                            [attr.aria-label]="'Change role of ' + u.username"
                            (click)="open('role', u)"
                          >
                            Role
                          </button>
                          <button
                            class="btn"
                            type="button"
                            [attr.aria-label]="'Reset password of ' + u.username"
                            (click)="open('password', u)"
                          >
                            Password
                          </button>
                          @if (u.disabled) {
                            <button
                              class="btn"
                              type="button"
                              [disabled]="busy()"
                              [attr.aria-label]="'Enable ' + u.username"
                              (click)="setDisabled(u, false)"
                            >
                              Enable
                            </button>
                          } @else {
                            <button
                              class="btn"
                              type="button"
                              [disabled]="isSelf(u)"
                              [attr.aria-label]="'Disable ' + u.username"
                              (click)="disabling.set(u)"
                            >
                              Disable
                            </button>
                          }
                          <button
                            class="btn btn-danger"
                            type="button"
                            [disabled]="isSelf(u)"
                            [attr.aria-label]="'Delete ' + u.username"
                            (click)="deleting.set(u)"
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          }
        }
      }
    </section>

    @if (dialog(); as d) {
      <app-user-dialog
        [mode]="d.mode"
        [target]="d.user?.username"
        [initialRole]="d.user?.role ?? 'viewer'"
        [busy]="busy()"
        [error]="actionError()"
        (saved)="save(d.mode, d.user, $event)"
        (cancelled)="closeDialog()"
      />
    }
    @if (disabling(); as u) {
      <app-confirm-dialog
        [heading]="'Disable ' + u.username"
        message="The user cannot log in, and their sessions and tokens stop working immediately. You can enable the account again later. The last active admin cannot be disabled."
        confirmLabel="Disable"
        [busy]="busy()"
        [error]="actionError()"
        (confirmed)="setDisabled(u, true)"
        (cancelled)="disabling.set(null)"
      />
    }
    @if (deleting(); as u) {
      <app-confirm-dialog
        [heading]="'Delete ' + u.username"
        message="The account, its sessions and its tokens stop working immediately. This cannot be undone."
        [busy]="busy()"
        [error]="actionError()"
        (confirmed)="remove(u)"
        (cancelled)="deleting.set(null)"
      />
    }
  `,
})
export class UsersPage {
  private readonly svc = inject(UsersService);
  private readonly auth = inject(AuthService);

  protected readonly users = signal<UserInfo[]>([]);
  protected readonly status = signal<'loading' | 'ready' | 'error'>('loading');
  protected readonly loadError = signal('Could not load users.');
  protected readonly busy = signal(false);
  protected readonly actionError = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly dialog = signal<{ mode: UserDialogMode; user?: UserInfo } | null>(null);
  protected readonly deleting = signal<UserInfo | null>(null);
  protected readonly disabling = signal<UserInfo | null>(null);
  protected readonly fmt = formatEpoch;

  constructor() {
    this.load();
  }

  protected isSelf(u: UserInfo): boolean {
    return this.auth.user()?.id === u.id;
  }

  protected load(): void {
    this.status.set('loading');
    this.svc.list().subscribe({
      next: (users) => {
        this.users.set(users);
        this.status.set('ready');
      },
      error: (e: unknown) => {
        this.loadError.set(messageOf(e, 'Could not load users.'));
        this.status.set('error');
      },
    });
  }

  protected open(mode: UserDialogMode, user?: UserInfo): void {
    this.actionError.set(null);
    this.dialog.set({ mode, user });
  }

  protected closeDialog(): void {
    this.dialog.set(null);
    this.actionError.set(null);
  }

  protected save(mode: UserDialogMode, user: UserInfo | undefined, v: UserFormValue): void {
    this.busy.set(true);
    this.actionError.set(null);
    const call =
      mode === 'create'
        ? this.svc.create({ username: v.username, password: v.password, role: v.role })
        : this.svc.update(user!.id, mode === 'role' ? { role: v.role } : { password: v.password });
    call.subscribe({
      next: () => {
        this.busy.set(false);
        this.dialog.set(null);
        this.notice.set(
          mode === 'create'
            ? 'User created.'
            : mode === 'role'
              ? 'Role updated.'
              : 'Password reset.',
        );
        this.load();
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.actionError.set(messageOf(e, 'Could not save the user.'));
      },
    });
  }

  protected setDisabled(u: UserInfo, disabled: boolean): void {
    this.busy.set(true);
    this.actionError.set(null);
    this.notice.set(null);
    this.svc.update(u.id, { disabled }).subscribe({
      next: () => {
        this.busy.set(false);
        this.disabling.set(null);
        this.notice.set(disabled ? `Disabled ${u.username}.` : `Enabled ${u.username}.`);
        this.load();
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.actionError.set(messageOf(e, 'Could not change the user.'));
        if (!disabled) this.notice.set(null);
      },
    });
  }

  protected remove(u: UserInfo): void {
    this.busy.set(true);
    this.actionError.set(null);
    this.svc.remove(u.id).subscribe({
      next: () => {
        this.busy.set(false);
        this.deleting.set(null);
        this.notice.set(`Deleted ${u.username}.`);
        this.load();
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.actionError.set(messageOf(e, 'Could not delete the user.'));
      },
    });
  }
}
