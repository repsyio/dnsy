import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
} from '../../shared/mascot';
import { formatEpoch, messageOf } from '../../shared/util/util';
import { ConfirmDialog } from '../../shared/ui/confirm-dialog';
import {
  MODE_TEXT,
  WEAKEN_TEXT,
  digestName,
  isWeakening,
  normalizeNta,
  ntaError,
  ntaExpiresAt,
  ntaExpiryError,
} from '../../core/dnssec-logic';
import { DnssecService } from '../../core/dnssec.service';
import type { DnssecStatus, ValidationMode, ValidationSettings } from '../../core/dnssec.service';

const MODES: ValidationMode[] = ['strict', 'permissive', 'off'];

/** DNSSEC validation: mode, negative trust anchors, trust anchors and answer counters. */
@Component({
  selector: 'app-validation-page',
  imports: [ConfirmDialog, MascotEmptyComponent, MascotErrorComponent, MascotLoadingComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1 class="mb-2 page-title">DNSSEC validation</h1>
    <p class="mb-6 max-w-2xl text-sm text-muted">
      When DNSY resolves for your clients it checks the DNSSEC signatures of answers. These settings
      change that check at run time; they are not written to the configuration file, so a restart
      returns to the configured mode.
    </p>

    @if (settings(); as s) {
      @if (status()?.clock_trusted === false) {
        <p class="mb-4 hairline border-amber p-3 text-sm text-amber" role="alert">
          The system clock is before the build time, so validation is suspended until it is correct.
        </p>
      }

      <section class="panel mb-6" aria-labelledby="vm-h">
        <h2 id="vm-h" class="mb-3 section-title">Validation mode</h2>
        <fieldset>
          <legend class="sr-only">Validation mode</legend>
          <div class="grid gap-3">
            @for (m of modes; track m) {
              <label class="flex items-start gap-3 text-sm" [attr.for]="'vm-' + m">
                <input
                  [id]="'vm-' + m"
                  type="radio"
                  name="mode"
                  class="mt-1"
                  [checked]="s.validation === m"
                  [disabled]="busy()"
                  (change)="pickMode(m)"
                />
                <span>
                  <span class="font-semibold capitalize">{{ m }}</span>
                  @if (m === 'strict') {
                    <span class="badge badge-ok ml-2">recommended</span>
                  }
                  <span class="block text-muted">{{ modeText[m] }}</span>
                </span>
              </label>
            }
          </div>
        </fieldset>
        @if (modeError()) {
          <p class="field-error mt-3" role="alert">{{ modeError() }}</p>
        }
        @if (notice()) {
          <p class="mt-3 text-sm text-secure" role="status">{{ notice() }}</p>
        }
        @if (status(); as st) {
          <dl class="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div>
              <dt class="text-xs uppercase tracking-wider text-muted">Secure answers</dt>
              <dd class="text-xl font-medium tabular-nums text-secure">{{ st.secure }}</dd>
            </div>
            <div>
              <dt class="text-xs uppercase tracking-wider text-muted">Bogus answers</dt>
              <dd class="text-xl font-medium tabular-nums text-amber">{{ st.bogus }}</dd>
            </div>
            <div>
              <dt class="text-xs uppercase tracking-wider text-muted">Signed zones</dt>
              <dd class="text-xl font-medium tabular-nums text-text">{{ st.signed_zones }}</dd>
            </div>
            <div>
              <dt class="text-xs uppercase tracking-wider text-muted">Window</dt>
              <dd class="text-sm">{{ hours(st.window_ms) }} h</dd>
            </div>
          </dl>
        }
      </section>

      <section class="panel mb-6" aria-labelledby="nta-h">
        <h2 id="nta-h" class="mb-2 section-title">Negative trust anchors</h2>
        <p class="mb-4 max-w-2xl text-sm text-muted">
          Validation is skipped at and below these names (RFC 7646). Use one to keep a zone
          reachable while its operator fixes a broken DNSSEC setup. Give the anchor an expiry so it
          stops applying by itself; without one it stays until you remove it. The list is cleared by
          a restart.
        </p>
        <form class="mb-4 flex flex-wrap items-end gap-3" novalidate (submit)="addNta($event)">
          <div>
            <label class="field-label" for="nta-name">Domain name</label>
            <input
              id="nta-name"
              class="field-input"
              placeholder="broken.example"
              autocomplete="off"
              [value]="ntaName()"
              [attr.aria-invalid]="ntaFormError() ? 'true' : null"
              (input)="ntaName.set(val($event))"
            />
          </div>
          <div>
            <label class="field-label" for="nta-hours">Expires in hours (optional)</label>
            <input
              id="nta-hours"
              class="field-input"
              inputmode="numeric"
              placeholder="24"
              autocomplete="off"
              [value]="ntaHours()"
              [attr.aria-invalid]="ntaFormError() ? 'true' : null"
              (input)="ntaHours.set(val($event))"
            />
          </div>
          <button class="btn" type="submit" [disabled]="busy()">Add</button>
        </form>
        @if (ntaFormError()) {
          <p class="field-error mb-3" role="alert">{{ ntaFormError() }}</p>
        }
        @if (s.negative_trust_anchor_entries.length === 0) {
          <dnsy-mascot-empty message="No negative trust anchors." />
        } @else {
          <ul class="grid gap-2">
            @for (n of s.negative_trust_anchor_entries; track n.name) {
              <li class="flex items-center justify-between gap-3 border-t-[0.5px] border-line py-2">
                <span class="break-all">
                  {{ n.name }}
                  <span class="block text-xs text-muted">
                    @if (n.expires_at) {
                      expires {{ fmt(n.expires_at) }}
                    } @else {
                      no expiry
                    }
                  </span>
                </span>
                <button
                  class="cursor-pointer text-amber underline"
                  type="button"
                  [disabled]="busy()"
                  [attr.aria-label]="'Remove negative trust anchor ' + n.name"
                  (click)="removing.set(n.name)"
                >
                  Remove
                </button>
              </li>
            }
          </ul>
        }
      </section>

      <section class="panel" aria-labelledby="ta-h">
        <h2 id="ta-h" class="mb-2 section-title">Trust anchors</h2>
        <p class="mb-4 max-w-2xl text-sm text-muted">
          The keys validation starts from, normally the root zone. They come from the configuration
          file and cannot be changed here.
        </p>
        @if (s.trust_anchors.length === 0) {
          <dnsy-mascot-empty message="No trust anchors configured." />
        } @else {
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
              <caption class="sr-only">
                Trust anchors
              </caption>
              <thead class="text-xs uppercase tracking-wider text-muted">
                <tr>
                  <th scope="col" class="py-2 pr-4">Zone</th>
                  <th scope="col" class="py-2 pr-4">Kind</th>
                  <th scope="col" class="py-2 pr-4">Key tag</th>
                  <th scope="col" class="py-2 pr-4">Algorithm</th>
                  <th scope="col" class="py-2">Digest</th>
                </tr>
              </thead>
              <tbody>
                @for (a of s.trust_anchors; track $index) {
                  <tr class="border-t-[0.5px] border-line">
                    <td class="py-2 pr-4">{{ a.owner }}</td>
                    <td class="py-2 pr-4 uppercase">{{ a.kind }}</td>
                    <td class="py-2 pr-4">{{ a.key_tag }}</td>
                    <td class="py-2 pr-4">{{ a.algorithm }}</td>
                    <td class="break-all py-2 text-xs">
                      @if (a.digest) {
                        {{ digest(a.digest_type ?? 0) }} {{ a.digest }}
                      } @else {
                        -
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </section>
    } @else if (state() === 'error') {
      <section class="panel">
        <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="load()" />
      </section>
    } @else {
      <section class="panel" aria-busy="true">
        <dnsy-mascot-loading message="Loading DNSSEC validation settings..." />
      </section>
    }

    @if (weakening(); as w) {
      <app-confirm-dialog
        heading="Weaken validation"
        [message]="weakenText(w)"
        [confirmLabel]="'Set ' + w"
        [busy]="busy()"
        [error]="modeError()"
        (confirmed)="applyMode(w)"
        (cancelled)="weakening.set(null)"
      />
    }
    @if (removing(); as n) {
      <app-confirm-dialog
        heading="Remove negative trust anchor"
        [message]="
          'Validation resumes at and below ' +
          n +
          '. If its DNSSEC is still broken, lookups there fail.'
        "
        confirmLabel="Remove"
        [busy]="busy()"
        [error]="modeError()"
        (confirmed)="removeNta(n)"
        (cancelled)="removing.set(null)"
      />
    }
  `,
})
export class ValidationPage {
  private readonly svc = inject(DnssecService);

  protected readonly modes = MODES;
  protected readonly modeText = MODE_TEXT;
  protected readonly digest = digestName;
  protected readonly settings = signal<ValidationSettings | null>(null);
  protected readonly status = signal<DnssecStatus | null>(null);
  protected readonly state = signal<'loading' | 'ready' | 'error'>('loading');
  protected readonly loadError = signal('Could not load the validation settings.');
  protected readonly busy = signal(false);
  protected readonly modeError = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly weakening = signal<ValidationMode | null>(null);
  protected readonly removing = signal<string | null>(null);
  protected readonly ntaName = signal('');
  protected readonly ntaHours = signal('');
  protected readonly fmt = formatEpoch;
  protected readonly ntaFormError = signal<string | null>(null);

  constructor() {
    this.load();
  }

  protected val(e: Event): string {
    return (e.target as HTMLInputElement).value;
  }
  protected hours(ms: number): number {
    return Math.round(ms / 3_600_000);
  }
  protected weakenText(m: ValidationMode): string {
    return `${WEAKEN_TEXT[m]} Continue?`;
  }

  protected load(): void {
    this.state.set('loading');
    this.svc.validation().subscribe({
      next: (s) => {
        this.settings.set(s);
        this.state.set('ready');
        this.svc.status().subscribe({ next: (st) => this.status.set(st), error: () => undefined });
      },
      error: (e: unknown) => {
        this.loadError.set(messageOf(e, 'Could not load the validation settings.'));
        this.state.set('error');
      },
    });
  }

  protected pickMode(m: ValidationMode): void {
    const cur = this.settings()?.validation;
    if (!cur || cur === m) return;
    this.modeError.set(null);
    this.notice.set(null);
    if (isWeakening(cur, m)) this.weakening.set(m);
    else this.applyMode(m);
  }

  protected applyMode(m: ValidationMode): void {
    this.patch({ validation: m }, `Validation mode is now ${m}.`);
  }

  protected addNta(event: Event): void {
    event.preventDefault();
    const list = this.settings()?.negative_trust_anchors ?? [];
    const err = ntaError(this.ntaName(), list) ?? ntaExpiryError(this.ntaHours());
    this.ntaFormError.set(err);
    if (err) return;
    const name = normalizeNta(this.ntaName());
    const expires_at = ntaExpiresAt(this.ntaHours(), Math.floor(Date.now() / 1000));
    const next = [...this.entries(), { name, expires_at }];
    this.patch({ negative_trust_anchors: next }, `Added ${name}.`, () => {
      this.ntaName.set('');
      this.ntaHours.set('');
    });
  }

  protected removeNta(name: string): void {
    const next = this.entries().filter((n) => n.name !== name);
    this.patch({ negative_trust_anchors: next }, `Removed ${name}.`);
  }

  /** The anchors in force, as the request body takes them (expiries are kept). */
  private entries(): { name: string; expires_at: number | null }[] {
    return (this.settings()?.negative_trust_anchor_entries ?? []).map((e) => ({
      name: e.name,
      expires_at: e.expires_at ?? null,
    }));
  }

  private patch(
    body: Parameters<DnssecService['patchValidation']>[0],
    done: string,
    after?: () => void,
  ): void {
    this.busy.set(true);
    this.modeError.set(null);
    this.svc.patchValidation(body).subscribe({
      next: (s) => {
        this.busy.set(false);
        this.settings.set(s);
        this.notice.set(done);
        this.weakening.set(null);
        this.removing.set(null);
        after?.();
        this.svc.status().subscribe({ next: (st) => this.status.set(st), error: () => undefined });
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.modeError.set(messageOf(e, 'The change was rejected.'));
      },
    });
  }
}
