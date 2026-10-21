import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { AuthService } from '../../core/auth.service';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
} from '../../shared/mascot';
import { formatEpoch, messageOf } from '../../shared/util/util';
import { ConfirmDialog } from '../../shared/ui/confirm-dialog';
import { copyText, dohUrl } from '../../shared/util/copy';
import { SecretDialog } from './secret-dialog';
import { CreatedToken, TokenInfo, TokensService, scopesForRole } from './tokens.service';

/** Own API tokens: create (secret shown once), list, revoke, and the DoH URL form. */
@Component({
  selector: 'app-tokens-page',
  imports: [
    ConfirmDialog,
    MascotEmptyComponent,
    MascotErrorComponent,
    MascotLoadingComponent,
    SecretDialog,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1 class="mb-6 page-title">API tokens</h1>

    <section class="panel mb-6" aria-labelledby="tc-h">
      <h2 id="tc-h" class="mb-4 section-title">Create token</h2>
      <form class="grid gap-4 md:grid-cols-2" novalidate (submit)="create($event)">
        <div>
          <label class="field-label" for="tc-name">Name</label>
          <input
            id="tc-name"
            class="field-input"
            autocomplete="off"
            [value]="name()"
            (input)="name.set(val($event))"
          />
        </div>
        <div>
          <label class="field-label" for="tc-exp">Expires (optional)</label>
          <input
            id="tc-exp"
            class="field-input"
            type="date"
            [value]="expiry()"
            (input)="expiry.set(val($event))"
          />
        </div>
        <fieldset class="md:col-span-2">
          <legend class="field-label">Scopes (limited to your role: {{ role() }})</legend>
          <div class="flex flex-wrap gap-4">
            @for (s of allowed(); track s) {
              <label class="flex items-center gap-2 text-sm" [for]="'tc-s-' + s">
                <input
                  type="checkbox"
                  [id]="'tc-s-' + s"
                  [checked]="scopes().includes(s)"
                  (change)="toggle(s, checked($event))"
                />
                {{ s }}
              </label>
            }
          </div>
        </fieldset>
        @if (formError(); as e) {
          <p class="field-error md:col-span-2" role="alert">{{ e }}</p>
        }
        <div class="md:col-span-2">
          <button class="btn" type="submit" [disabled]="busy()">Create token</button>
        </div>
      </form>
    </section>

    <section class="panel mb-6" aria-labelledby="td-h">
      <h2 id="td-h" class="mb-2 section-title">DNS over HTTPS</h2>
      <p class="mb-3 text-sm text-muted">
        A token with the <code>dns:query</code> scope authenticates DoH clients in the URL path.
      </p>
      <div class="flex flex-wrap items-center gap-3">
        <code class="break-all text-sm">{{ template }}</code>
        <button class="btn" type="button" (click)="copyTemplate()">Copy URL</button>
      </div>
      <p class="mt-2 text-sm text-secure" role="status">{{ copied() }}</p>
    </section>

    <section class="panel" aria-labelledby="tl-h">
      <h2 id="tl-h" class="mb-4 section-title">Your tokens</h2>
      @if (notice(); as n) {
        <p class="mb-3 text-sm text-secure" role="status">{{ n }}</p>
      }
      @switch (status()) {
        @case ('loading') {
          <div aria-busy="true"><dnsy-mascot-loading message="Loading tokens..." /></div>
        }
        @case ('error') {
          <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="load()" />
        }
        @default {
          @if (tokens().length === 0) {
            <dnsy-mascot-empty message="No tokens yet." />
          } @else {
            <div class="overflow-x-auto">
              <table class="w-full text-left text-sm">
                <caption class="sr-only">
                  Tokens
                </caption>
                <thead class="text-xs uppercase tracking-wider text-muted">
                  <tr>
                    <th scope="col" class="py-2 pr-4">Name</th>
                    <th scope="col" class="py-2 pr-4">Scopes</th>
                    <th scope="col" class="py-2 pr-4">Last used</th>
                    <th scope="col" class="py-2 pr-4">Expires</th>
                    <th scope="col" class="py-2 pr-4">Status</th>
                    <th scope="col" class="py-2"><span class="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  @for (t of tokens(); track t.id) {
                    <tr class="border-t-[0.5px] border-line">
                      <td class="py-2 pr-4 break-all">{{ t.name }}</td>
                      <td class="py-2 pr-4">{{ t.scopes.join(', ') }}</td>
                      <td class="py-2 pr-4 whitespace-nowrap">{{ fmt(t.last_used_at) }}</td>
                      <td class="py-2 pr-4 whitespace-nowrap">
                        {{ t.expires_at ? fmt(t.expires_at) : 'never' }}
                      </td>
                      <td class="py-2 pr-4">
                        <span
                          class="badge"
                          [class.badge-ok]="!t.revoked"
                          [class.badge-warn]="t.revoked"
                          >{{ t.revoked ? 'revoked' : 'active' }}</span
                        >
                      </td>
                      <td class="py-2">
                        @if (!t.revoked) {
                          <button
                            class="btn btn-danger"
                            type="button"
                            [attr.aria-label]="'Revoke token ' + t.name"
                            (click)="revoking.set(t)"
                          >
                            Revoke
                          </button>
                        }
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

    @if (created(); as c) {
      <app-secret-dialog
        [name]="c.meta.name"
        [secret]="c.token"
        [doh]="c.meta.scopes.includes('dns:query')"
        (done)="dismissSecret()"
      />
    }
    @if (revoking(); as t) {
      <app-confirm-dialog
        [heading]="'Revoke ' + t.name"
        message="Clients using this token stop working immediately. This cannot be undone."
        confirmLabel="Revoke"
        [busy]="busy()"
        [error]="actionError()"
        (confirmed)="revoke(t)"
        (cancelled)="revoking.set(null)"
      />
    }
  `,
})
export class TokensPage {
  private readonly svc = inject(TokensService);
  private readonly auth = inject(AuthService);

  protected readonly template = dohUrl(location.host);
  protected readonly role = computed(() => this.auth.user()?.role ?? 'viewer');
  protected readonly allowed = computed(() => scopesForRole(this.role()));
  protected readonly tokens = signal<TokenInfo[]>([]);
  protected readonly status = signal<'loading' | 'ready' | 'error'>('loading');
  protected readonly loadError = signal('Could not load tokens.');
  protected readonly name = signal('');
  protected readonly expiry = signal('');
  protected readonly scopes = signal<string[]>([]);
  protected readonly formError = signal<string | null>(null);
  protected readonly actionError = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly copied = signal('');
  protected readonly busy = signal(false);
  /** The only place the secret lives; cleared when the dialog closes. */
  protected readonly created = signal<CreatedToken | null>(null);
  protected readonly revoking = signal<TokenInfo | null>(null);
  protected readonly fmt = formatEpoch;

  constructor() {
    this.load();
  }

  protected val(e: Event): string {
    return (e.target as HTMLInputElement).value;
  }

  protected checked(e: Event): boolean {
    return (e.target as HTMLInputElement).checked;
  }

  protected toggle(scope: string, on: boolean): void {
    this.scopes.update((s) => (on ? [...s, scope] : s.filter((x) => x !== scope)));
  }

  protected load(): void {
    this.status.set('loading');
    this.svc.list().subscribe({
      next: (t) => {
        this.tokens.set(t);
        this.status.set('ready');
      },
      error: (e: unknown) => {
        this.loadError.set(messageOf(e, 'Could not load tokens.'));
        this.status.set('error');
      },
    });
  }

  protected async copyTemplate(): Promise<void> {
    this.copied.set((await copyText(this.template)) ? 'URL copied.' : 'Copy failed.');
  }

  protected create(event: Event): void {
    event.preventDefault();
    const name = this.name().trim();
    this.notice.set(null);
    if (!name) {
      this.formError.set('Enter a name for the token.');
      return;
    }
    if (this.scopes().length === 0) {
      this.formError.set('Pick at least one scope.');
      return;
    }
    let expires_at: number | null = null;
    if (this.expiry()) {
      expires_at = Math.floor(Date.parse(`${this.expiry()}T23:59:59Z`) / 1000);
      if (!Number.isFinite(expires_at) || expires_at * 1000 <= Date.now()) {
        this.formError.set('The expiry must be in the future.');
        return;
      }
    }
    this.formError.set(null);
    this.busy.set(true);
    this.svc.create({ name, scopes: this.scopes(), expires_at }).subscribe({
      next: (c) => {
        this.busy.set(false);
        this.created.set(c);
        this.name.set('');
        this.expiry.set('');
        this.scopes.set([]);
        this.load();
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.formError.set(messageOf(e, 'Could not create the token.'));
      },
    });
  }

  /** Forget the secret. Nothing else keeps a copy. */
  protected dismissSecret(): void {
    this.created.set(null);
  }

  protected revoke(t: TokenInfo): void {
    this.busy.set(true);
    this.actionError.set(null);
    this.svc.revoke(t.id).subscribe({
      next: () => {
        this.busy.set(false);
        this.revoking.set(null);
        this.notice.set(`Revoked ${t.name}.`);
        this.load();
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.actionError.set(messageOf(e, 'Could not revoke the token.'));
      },
    });
  }
}
