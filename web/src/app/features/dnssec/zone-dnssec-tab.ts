import {
  ChangeDetectionStrategy,
  Component,
  effect,
  inject,
  input,
  output,
  signal,
  untracked,
} from '@angular/core';
import type { Observable } from 'rxjs';
import { MascotErrorComponent, MascotLoadingComponent } from '../../shared/mascot';
import { formatEpoch, messageOf } from '../admin-shared/util';
import { ConfirmDialog } from '../zones/confirm-dialog';
import { ZonesService, downloadText } from '../zones/zones.service';
import {
  ALGORITHMS,
  algorithmName,
  digestName,
  keyTimers,
  nsec3Error,
  orderDs,
  preferredDs,
} from './dnssec-logic';
import { DnssecService } from './dnssec.service';
import type { DnssecPolicyInput, DnssecView, DsExport, KeyView } from './dnssec.service';

type Status = 'loading' | 'ready' | 'error';
type Action =
  | { kind: 'enable' }
  | { kind: 'disable' }
  | { kind: 'rollover'; key: KeyView }
  | { kind: 'confirm-ds'; key: KeyView };

const REGISTRAR_ENABLE =
  'DNSY will create the keys and sign the zone now. Signing alone does not make the zone secure: ' +
  'you must then publish the DS record at your registrar (copy it from the DS section and add it ' +
  'in the registrar control panel). Until the DS is published, validating resolvers treat the zone as unsigned.';
const REGISTRAR_DISABLE =
  'Remove the DS record at your registrar first and wait for its TTL to pass. If the DS stays ' +
  'while the zone is unsigned, validating resolvers return SERVFAIL for every name in this zone. ' +
  'Disabling stops signing and removes the signatures from served answers.';
const REGISTRAR_ROLLOVER =
  'A new key is generated and published next to the old one. For a KSK or CSK you must then ' +
  'publish the new key DS at your registrar and confirm it here; the old key is retired only ' +
  'after that. Keep the old DS until the rollover finishes.';

/** DNSSEC tab of the zone editor: signing policy, keys and rollover, DS for the registrar. */
@Component({
  selector: 'app-zone-dnssec-tab',
  imports: [ConfirmDialog, MascotErrorComponent, MascotLoadingComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @switch (status()) {
      @case ('loading') {
        <dnsy-mascot-loading message="Loading DNSSEC state..." />
      }
      @case ('error') {
        <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="load()" />
      }
      @default {
        @if (view(); as v) {
          @if (v.enabled && !v.keys_encrypted) {
            <p class="mb-4 border border-orange p-3 text-sm text-orange" role="alert">
              Private keys are not encrypted at rest. Set a key passphrase (<code
                >DNSY_DNSSEC_PASSPHRASE</code
              >
              or <code>dnssec.key_passphrase_file</code>) so new keys are protected.
            </p>
          }
          @if (error()) {
            <p class="field-error mb-4" role="alert">{{ error() }}</p>
          }
          @if (notice()) {
            <p class="mb-4 text-sm text-secure" role="status">{{ notice() }}</p>
          }

          @if (!v.enabled) {
            <h2 class="mb-2 text-lg text-cyan">Sign this zone</h2>
            <p class="mb-4 text-sm text-muted">
              DNSSEC adds signatures to the zone so resolvers can prove answers are genuine. After
              enabling you publish a DS record at your registrar.
            </p>
            <form class="grid max-w-xl gap-4" novalidate (submit)="askEnable($event)">
              <div>
                <label class="field-label" for="dn-alg">Algorithm</label>
                <select
                  id="dn-alg"
                  class="field-input"
                  [value]="algorithm()"
                  (change)="algorithm.set(num($event))"
                >
                  @for (a of algorithms; track a.id) {
                    <option [value]="a.id" [selected]="a.id === algorithm()">{{ a.label }}</option>
                  }
                </select>
              </div>
              <div>
                <label class="field-label" for="dn-layout">Key layout</label>
                <select
                  id="dn-layout"
                  class="field-input"
                  [value]="layout()"
                  (change)="layout.set(str($event) === 'ksk_zsk' ? 'ksk_zsk' : 'csk')"
                >
                  <option value="csk" [selected]="layout() === 'csk'">
                    One combined key (CSK), simplest
                  </option>
                  <option value="ksk_zsk" [selected]="layout() === 'ksk_zsk'">
                    Separate KSK and ZSK
                  </option>
                </select>
              </div>
              <fieldset>
                <legend class="field-label">Authenticated denial of existence</legend>
                <label class="mr-4 inline-flex items-center gap-2 text-sm" for="dn-nsec3">
                  <input
                    id="dn-nsec3"
                    type="radio"
                    name="denial"
                    [checked]="denial() === 'nsec3'"
                    (change)="denial.set('nsec3')"
                  />
                  NSEC3 (hides names)
                </label>
                <label class="inline-flex items-center gap-2 text-sm" for="dn-nsec">
                  <input
                    id="dn-nsec"
                    type="radio"
                    name="denial"
                    [checked]="denial() === 'nsec'"
                    (change)="denial.set('nsec')"
                  />
                  NSEC (plain, lists names)
                </label>
              </fieldset>
              @if (denial() === 'nsec3') {
                <div class="grid gap-4 border border-cyan/30 p-4 sm:grid-cols-2">
                  <div>
                    <label class="field-label" for="dn-salt">Salt (hex, optional)</label>
                    <input
                      id="dn-salt"
                      class="field-input"
                      autocomplete="off"
                      [value]="salt()"
                      [attr.aria-invalid]="formError() ? 'true' : null"
                      (input)="salt.set(str($event))"
                    />
                  </div>
                  <div>
                    <label class="field-label" for="dn-iter">Iterations</label>
                    <input
                      id="dn-iter"
                      class="field-input"
                      inputmode="numeric"
                      [value]="iterations()"
                      [attr.aria-invalid]="formError() ? 'true' : null"
                      (input)="iterations.set(str($event))"
                    />
                  </div>
                  <label class="flex items-center gap-2 text-sm" for="dn-nonzero">
                    <input
                      id="dn-nonzero"
                      type="checkbox"
                      [checked]="allowNonzero()"
                      (change)="allowNonzero.set(checked($event))"
                    />
                    Allow non-zero iterations (RFC 9276 advises 0)
                  </label>
                  <label class="flex items-center gap-2 text-sm" for="dn-optout">
                    <input
                      id="dn-optout"
                      type="checkbox"
                      [checked]="optOut()"
                      (change)="optOut.set(checked($event))"
                    />
                    Opt-out (skip unsigned delegations)
                  </label>
                </div>
              }
              @if (formError()) {
                <p class="field-error" role="alert">{{ formError() }}</p>
              }
              <div>
                <button class="btn" type="submit" [disabled]="busy()">Enable DNSSEC signing</button>
              </div>
            </form>
          } @else {
            <div class="mb-6 flex flex-wrap items-start justify-between gap-3">
              <dl class="grid grid-cols-2 gap-4 sm:grid-cols-4">
                <div>
                  <dt class="text-xs uppercase tracking-wider text-muted">Algorithm</dt>
                  <dd>{{ algName(v.algorithm) }}</dd>
                </div>
                <div>
                  <dt class="text-xs uppercase tracking-wider text-muted">Denial</dt>
                  <dd>
                    {{ v.denial === 'nsec3' ? 'NSEC3' : 'NSEC' }}
                    @if (v.denial === 'nsec3') {
                      <span class="text-xs text-muted">
                        ({{ v.nsec3.iterations ?? 0 }} iterations{{
                          v.nsec3.opt_out ? ', opt-out' : ''
                        }})
                      </span>
                    }
                  </dd>
                </div>
                <div>
                  <dt class="text-xs uppercase tracking-wider text-muted">Signatures</dt>
                  <dd>
                    {{ v.signature_validity_days }} days, refreshed {{ v.refresh_days }} days early
                  </dd>
                </div>
                <div>
                  <dt class="text-xs uppercase tracking-wider text-muted">Next re-sign</dt>
                  <dd>{{ fmt(v.next_resign) }}</dd>
                </div>
              </dl>
              <div class="flex flex-wrap gap-3">
                <button class="btn" type="button" [disabled]="busy()" (click)="download()">
                  Download signed export
                </button>
                <button
                  class="btn btn-danger"
                  type="button"
                  [disabled]="busy()"
                  (click)="action.set({ kind: 'disable' })"
                >
                  Disable signing
                </button>
              </div>
            </div>

            @if (v.rollover.state !== 'idle') {
              <p class="mb-4 border border-cyan/30 p-3 text-sm" role="status">
                Rollover of the {{ v.rollover.role ?? 'key' }}:
                @if (v.rollover.state === 'awaiting_ds_confirmation') {
                  waiting for you to publish the new DS at the registrar and confirm it below.
                } @else {
                  in progress, it finishes by itself.
                }
              </p>
            }

            <h2 class="mb-2 text-lg text-cyan">Keys</h2>
            <div class="mb-6 overflow-x-auto">
              <table class="w-full text-left text-sm">
                <caption class="sr-only">
                  DNSSEC keys
                </caption>
                <thead class="text-xs uppercase tracking-wider text-muted">
                  <tr>
                    <th scope="col" class="py-2 pr-4">Role</th>
                    <th scope="col" class="py-2 pr-4">Tag</th>
                    <th scope="col" class="py-2 pr-4">State</th>
                    <th scope="col" class="py-2 pr-4">Timers</th>
                    <th scope="col" class="py-2"><span class="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  @for (k of v.keys; track k.id) {
                    <tr class="border-t border-cyan/20 align-top">
                      <td class="py-2 pr-4 uppercase">{{ k.role }}</td>
                      <td class="py-2 pr-4">{{ k.key_tag }}</td>
                      <td class="py-2 pr-4">
                        <span class="badge" [class.badge-ok]="k.state === 'active'">{{
                          k.state
                        }}</span>
                      </td>
                      <td class="py-2 pr-4 text-xs text-muted">
                        @for (t of timers(k); track t.label) {
                          <div>{{ t.label }} {{ fmt(t.at) }}</div>
                        }
                        @if (k.ds_confirmed_at) {
                          <div>DS confirmed {{ fmt(k.ds_confirmed_at) }}</div>
                        }
                      </td>
                      <td class="whitespace-nowrap py-2">
                        @if (needsDsConfirm(k)) {
                          <button
                            class="mr-3 cursor-pointer text-cyan underline"
                            type="button"
                            [attr.aria-label]="'DS confirmed at registrar for key ' + k.key_tag"
                            (click)="action.set({ kind: 'confirm-ds', key: k })"
                          >
                            DS confirmed at registrar
                          </button>
                        }
                        @if (k.state === 'active' && v.rollover.state === 'idle') {
                          <button
                            class="cursor-pointer text-orange underline"
                            type="button"
                            [attr.aria-label]="'Start rollover of key ' + k.key_tag"
                            (click)="action.set({ kind: 'rollover', key: k })"
                          >
                            Start rollover
                          </button>
                        }
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>

            <h2 class="mb-2 text-lg text-cyan">DS records for the registrar</h2>
            <p class="mb-3 text-sm text-muted">
              Add one DS record at your registrar. Use SHA-256 unless the registrar only offers
              SHA-384. Registrars that take keys want the DNSKEY instead.
            </p>
            @if (ds(); as d) {
              @if (d.ds.length === 0) {
                <p class="text-sm text-muted">No DS available yet: no published KSK or CSK.</p>
              } @else {
                <ul class="mb-3 grid gap-3">
                  @for (r of dsOrdered(d); track r.record) {
                    <li class="border border-cyan/30 p-3">
                      <p class="mb-1 text-xs text-muted">
                        Key {{ r.key_tag }}, {{ digest(r.digest_type) }}
                      </p>
                      <code class="block break-all text-sm">{{ r.record }}</code>
                      <button
                        class="btn mt-2"
                        type="button"
                        [attr.aria-label]="
                          'Copy DS record for key ' + r.key_tag + ' ' + digest(r.digest_type)
                        "
                        (click)="copy(r.record, 'DS record')"
                      >
                        Copy
                      </button>
                    </li>
                  }
                </ul>
                <button class="btn mb-4" type="button" (click)="copyPreferred(d)">
                  Copy for registrar (SHA-256)
                </button>
              }
              @if (d.dnskey.length > 0) {
                <h3 class="mb-2 mt-4 text-sm text-cyan">DNSKEY records</h3>
                <ul class="grid gap-3">
                  @for (r of d.dnskey; track r.record) {
                    <li class="border border-cyan/30 p-3">
                      <code class="block break-all text-sm">{{ r.record }}</code>
                      <button
                        class="btn mt-2"
                        type="button"
                        [attr.aria-label]="'Copy DNSKEY record for key ' + r.key_tag"
                        (click)="copy(r.record, 'DNSKEY record')"
                      >
                        Copy
                      </button>
                    </li>
                  }
                </ul>
              }
            }
          }
        }
      }
    }

    @if (action(); as a) {
      <app-confirm-dialog
        [heading]="heading(a)"
        [message]="message(a)"
        [confirmLabel]="confirmLabel(a)"
        [phrase]="a.kind === 'disable' ? zone() : null"
        [busy]="busy()"
        [error]="dialogError()"
        (confirmed)="run(a)"
        (cancelled)="closeAction()"
      />
    }
  `,
})
export class ZoneDnssecTab {
  /** Zone name. */
  readonly zone = input.required<string>();
  /** Signing was turned on or off, so the zone header should refresh. */
  readonly changed = output<void>();

  private readonly svc = inject(DnssecService);
  private readonly zones = inject(ZonesService);

  protected readonly algorithms = ALGORITHMS;
  protected readonly status = signal<Status>('loading');
  protected readonly loadError = signal('Could not load the DNSSEC state.');
  protected readonly view = signal<DnssecView | null>(null);
  protected readonly ds = signal<DsExport | null>(null);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly dialogError = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly action = signal<Action | null>(null);
  protected readonly formError = signal<string | null>(null);

  protected readonly algorithm = signal<number>(13);
  protected readonly layout = signal<'csk' | 'ksk_zsk'>('csk');
  protected readonly denial = signal<'nsec' | 'nsec3'>('nsec3');
  protected readonly salt = signal('');
  protected readonly iterations = signal('0');
  protected readonly allowNonzero = signal(false);
  protected readonly optOut = signal(false);

  protected readonly algName = algorithmName;
  protected readonly digest = digestName;
  protected readonly timers = keyTimers;
  protected readonly dsOrdered = (d: DsExport) => orderDs(d.ds);

  constructor() {
    effect(() => {
      this.zone();
      untracked(() => this.load());
    });
  }

  protected str(e: Event): string {
    return (e.target as HTMLInputElement).value;
  }
  protected num(e: Event): number {
    return Number(this.str(e));
  }
  protected checked(e: Event): boolean {
    return (e.target as HTMLInputElement).checked;
  }
  protected fmt(secs: number | null | undefined): string {
    return formatEpoch(secs);
  }

  protected needsDsConfirm(k: KeyView): boolean {
    return (
      (k.role === 'ksk' || k.role === 'csk') &&
      !k.ds_confirmed_at &&
      (k.state === 'published' || k.state === 'active')
    );
  }

  protected load(silent = false): void {
    if (!silent) this.status.set('loading');
    this.svc.view(this.zone()).subscribe({
      next: (v) => {
        this.view.set(v);
        this.status.set('ready');
        if (v.enabled) this.loadDs();
        else this.ds.set(null);
      },
      error: (e: unknown) => {
        this.loadError.set(messageOf(e, 'Could not load the DNSSEC state.'));
        this.status.set('error');
      },
    });
  }

  private loadDs(): void {
    this.svc.ds(this.zone()).subscribe({
      next: (d) => this.ds.set(d),
      error: (e: unknown) => this.error.set(messageOf(e, 'Could not load the DS records.')),
    });
  }

  protected askEnable(event: Event): void {
    event.preventDefault();
    const err =
      this.denial() === 'nsec3'
        ? nsec3Error(this.salt(), this.iterations(), this.allowNonzero())
        : null;
    this.formError.set(err);
    if (!err) this.action.set({ kind: 'enable' });
  }

  protected heading(a: Action): string {
    switch (a.kind) {
      case 'enable':
        return 'Enable DNSSEC signing';
      case 'disable':
        return 'Disable DNSSEC signing';
      case 'rollover':
        return `Start rollover of key ${a.key.key_tag}`;
      case 'confirm-ds':
        return 'Confirm DS at registrar';
    }
  }

  protected message(a: Action): string {
    switch (a.kind) {
      case 'enable':
        return REGISTRAR_ENABLE;
      case 'disable':
        return REGISTRAR_DISABLE;
      case 'rollover':
        return REGISTRAR_ROLLOVER;
      case 'confirm-ds':
        return `Confirm only after the DS record for key ${a.key.key_tag} is live at the registrar. DNSY then moves on to retire the old key.`;
    }
  }

  protected confirmLabel(a: Action): string {
    switch (a.kind) {
      case 'enable':
        return 'Enable signing';
      case 'disable':
        return 'Disable signing';
      case 'rollover':
        return 'Start rollover';
      case 'confirm-ds':
        return 'DS is published';
    }
  }

  protected closeAction(): void {
    this.action.set(null);
    this.dialogError.set(null);
  }

  private policy(): DnssecPolicyInput {
    const base: DnssecPolicyInput = {
      enabled: true,
      algorithm: this.algorithm(),
      key_layout: this.layout(),
      denial: this.denial(),
    };
    if (this.denial() === 'nsec3') {
      base.nsec3 = {
        salt: this.salt().trim(),
        iterations: this.iterations().trim() === '' ? 0 : Number(this.iterations()),
        allow_nonzero_iterations: this.allowNonzero(),
        opt_out: this.optOut(),
      };
    }
    return base;
  }

  protected run(a: Action): void {
    const zone = this.zone();
    this.busy.set(true);
    this.dialogError.set(null);
    this.error.set(null);
    this.notice.set(null);
    let call: Observable<unknown>;
    let done: string;
    switch (a.kind) {
      case 'enable':
        call = this.svc.setPolicy(zone, this.policy());
        done = 'Signing enabled. Publish the DS record at your registrar.';
        break;
      case 'disable':
        call = this.svc.setPolicy(zone, { enabled: false });
        done = 'Signing disabled.';
        break;
      case 'rollover':
        call = this.svc.rollover(zone, a.key.id);
        done = 'Rollover started.';
        break;
      case 'confirm-ds':
        call = this.svc.confirmDs(zone, a.key.id);
        done = 'DS confirmed.';
        break;
    }
    call.subscribe({
      next: (res) => {
        this.busy.set(false);
        this.closeAction();
        this.notice.set(done);
        if (a.kind === 'enable' || a.kind === 'disable') {
          const v = res as DnssecView;
          this.view.set(v);
          if (v.enabled) this.loadDs();
          else this.ds.set(null);
          this.changed.emit();
        } else {
          this.load(true);
        }
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.dialogError.set(messageOf(e, 'The change was rejected.'));
      },
    });
  }

  protected copyPreferred(d: DsExport): void {
    const r = preferredDs(d.ds);
    if (r) this.copy(r.record, 'DS record');
  }

  protected copy(text: string, what: string): void {
    this.error.set(null);
    this.notice.set(null);
    const clip = navigator.clipboard as Clipboard | undefined;
    if (!clip) {
      this.error.set('Copy is not available in this browser; select the text instead.');
      return;
    }
    clip.writeText(text).then(
      () => this.notice.set(`${what} copied.`),
      () => this.error.set('Copy was blocked; select the text instead.'),
    );
  }

  protected download(): void {
    const name = this.zone();
    this.busy.set(true);
    this.error.set(null);
    this.zones.exportZone(name, true).subscribe({
      next: (text) => {
        this.busy.set(false);
        downloadText(`${name.replace(/\.$/, '') || 'root'}.signed.zone`, text);
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.error.set(messageOf(e, 'Export failed.'));
      },
    });
  }
}
