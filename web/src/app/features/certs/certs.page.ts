import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
} from '../../shared/mascot';
import { formatEpoch, messageOf } from '../../shared/util/util';
import { ConfirmDialog } from '../../shared/ui/confirm-dialog';
import { CertsService } from './certs.service';
import type { ClientCert } from './certs.service';
import { expiryFromDate, parseFingerprint } from './fingerprint';

/** Client certificate fingerprint allowlist for DoT mutual TLS. */
@Component({
  selector: 'app-certs-page',
  imports: [ConfirmDialog, MascotEmptyComponent, MascotErrorComponent, MascotLoadingComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1 class="mb-6 text-2xl font-bold text-cyan">Client certificates</h1>

    @switch (status()) {
      @case ('loading') {
        <section class="panel" aria-busy="true">
          <dnsy-mascot-loading message="Loading certificates..." />
        </section>
      }
      @case ('error') {
        <section class="panel">
          <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="load()" />
        </section>
      }
      @default {
        <section class="panel mb-6" aria-labelledby="cc-add">
          <h2 id="cc-add" class="mb-4 text-lg text-cyan">Allow a certificate</h2>
          <form class="grid grid-cols-1 gap-3 sm:grid-cols-6" novalidate (submit)="add($event)">
            <div class="sm:col-span-3">
              <label class="field-label" for="cc-fp">SHA-256 fingerprint</label>
              <input
                id="cc-fp"
                class="field-input"
                autocomplete="off"
                [value]="fingerprint()"
                [attr.aria-invalid]="errors().fingerprint ? 'true' : null"
                (input)="fingerprint.set(val($event))"
              />
              @if (errors().fingerprint; as e) {
                <p class="field-error" role="alert">{{ e }}</p>
              }
            </div>
            <div>
              <label class="field-label" for="cc-label">Label</label>
              <input
                id="cc-label"
                class="field-input"
                autocomplete="off"
                [value]="label()"
                [attr.aria-invalid]="errors().label ? 'true' : null"
                (input)="label.set(val($event))"
              />
              @if (errors().label; as e) {
                <p class="field-error" role="alert">{{ e }}</p>
              }
            </div>
            <div>
              <label class="field-label" for="cc-exp">Expires (optional)</label>
              <input
                id="cc-exp"
                class="field-input"
                type="date"
                [value]="expires()"
                (input)="expires.set(val($event))"
              />
              @if (errors().expires; as e) {
                <p class="field-error" role="alert">{{ e }}</p>
              }
            </div>
            <div class="flex items-end">
              <button class="btn w-full" type="submit" [disabled]="busy()">Add</button>
            </div>
          </form>
          @if (formError(); as e) {
            <p class="field-error mt-2" role="alert">{{ e }}</p>
          }
        </section>

        <section class="panel" aria-labelledby="cc-list">
          <h2 id="cc-list" class="mb-4 text-lg text-cyan">Allowed certificates</h2>
          @if (actionError(); as e) {
            <p class="field-error mb-3" role="alert">{{ e }}</p>
          }
          @if (certs().length === 0) {
            <dnsy-mascot-empty message="No client certificates are allowed yet." />
          } @else {
            <div class="overflow-x-auto">
              <table class="w-full text-left text-sm">
                <caption class="sr-only">
                  Allowed client certificates
                </caption>
                <thead class="text-xs uppercase tracking-wider text-muted">
                  <tr>
                    <th scope="col" class="py-2 pr-4">Label</th>
                    <th scope="col" class="py-2 pr-4">Fingerprint</th>
                    <th scope="col" class="py-2 pr-4">Expires</th>
                    <th scope="col" class="py-2 pr-4">Status</th>
                    <th scope="col" class="py-2">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  @for (c of certs(); track c.id) {
                    <tr class="border-t border-cyan/20 align-top">
                      <td class="py-2 pr-4">{{ c.label }}</td>
                      <td class="py-2 pr-4 break-all text-xs">{{ c.sha256 }}</td>
                      <td class="py-2 pr-4">{{ fmt(c.expires_at) }}</td>
                      <td class="py-2 pr-4">
                        @if (c.expired) {
                          <span class="badge badge-warn">expired</span>
                        } @else if (c.enabled) {
                          <span class="badge badge-ok">enabled</span>
                        } @else {
                          <span class="badge badge-warn">disabled</span>
                        }
                      </td>
                      <td class="py-2">
                        <div class="flex flex-wrap gap-2">
                          <button
                            class="btn"
                            type="button"
                            [attr.aria-label]="(c.enabled ? 'Disable ' : 'Enable ') + c.label"
                            (click)="toggle(c)"
                          >
                            {{ c.enabled ? 'Disable' : 'Enable' }}
                          </button>
                          <button
                            class="btn btn-danger"
                            type="button"
                            [attr.aria-label]="'Remove ' + c.label"
                            (click)="pending.set(c)"
                          >
                            Remove
                          </button>
                        </div>
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          }
        </section>
      }
    }

    @if (pending(); as c) {
      <app-confirm-dialog
        heading="Remove client certificate"
        [message]="
          'Remove ' + c.label + '? Clients presenting it can no longer connect over mutual TLS.'
        "
        confirmLabel="Remove"
        [busy]="busy()"
        (confirmed)="confirmRemove(c)"
        (cancelled)="pending.set(null)"
      />
    }
  `,
})
export class CertsPage {
  private readonly svc = inject(CertsService);

  protected readonly certs = signal<ClientCert[]>([]);
  protected readonly status = signal<'loading' | 'ready' | 'error'>('loading');
  protected readonly loadError = signal('Could not load certificates.');
  protected readonly busy = signal(false);
  protected readonly fingerprint = signal('');
  protected readonly label = signal('');
  protected readonly expires = signal('');
  protected readonly errors = signal<{ fingerprint?: string; label?: string; expires?: string }>(
    {},
  );
  protected readonly formError = signal<string | null>(null);
  protected readonly actionError = signal<string | null>(null);
  protected readonly pending = signal<ClientCert | null>(null);

  constructor() {
    this.load();
  }

  protected val(e: Event): string {
    return (e.target as HTMLInputElement).value;
  }

  protected fmt(secs: number | null | undefined): string {
    return secs == null ? 'never' : formatEpoch(secs);
  }

  protected load(): void {
    this.status.set('loading');
    this.svc.list().subscribe({
      next: (c) => {
        this.certs.set(c);
        this.status.set('ready');
      },
      error: (e: unknown) => {
        this.loadError.set(messageOf(e, 'Could not load certificates.'));
        this.status.set('error');
      },
    });
  }

  protected add(event: Event): void {
    event.preventDefault();
    const fp = parseFingerprint(this.fingerprint());
    const label = this.label().trim();
    const exp = expiryFromDate(this.expires());
    const errors: { fingerprint?: string; label?: string; expires?: string } = {};
    if ('error' in fp) errors.fingerprint = fp.error;
    if (!label) errors.label = 'A label is required.';
    if (exp === 'invalid') errors.expires = 'Use a valid date.';
    this.errors.set(errors);
    if ('error' in fp || exp === 'invalid' || !label) return;
    this.formError.set(null);
    this.busy.set(true);
    this.svc.add({ sha256: fp.value, label, expires_at: exp }).subscribe({
      next: (c) => {
        this.busy.set(false);
        this.certs.update((all) => [...all, c]);
        this.fingerprint.set('');
        this.label.set('');
        this.expires.set('');
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.formError.set(messageOf(e, 'Could not add the certificate.'));
      },
    });
  }

  protected toggle(c: ClientCert): void {
    this.actionError.set(null);
    this.svc.setEnabled(c.id, !c.enabled).subscribe({
      next: (u) => this.certs.update((all) => all.map((x) => (x.id === u.id ? u : x))),
      error: (e: unknown) =>
        this.actionError.set(messageOf(e, 'Could not update the certificate.')),
    });
  }

  protected confirmRemove(c: ClientCert): void {
    this.busy.set(true);
    this.svc.remove(c.id).subscribe({
      next: () => {
        this.busy.set(false);
        this.pending.set(null);
        this.certs.update((all) => all.filter((x) => x.id !== c.id));
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.pending.set(null);
        this.actionError.set(messageOf(e, 'Could not remove the certificate.'));
      },
    });
  }
}
