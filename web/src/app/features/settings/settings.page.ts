import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { MascotErrorComponent, MascotLoadingComponent } from '../../shared/mascot';
import { messageOf } from '../admin-shared/util';
import { SettingsService } from './settings.service';
import type { BlockMode, Settings } from './settings.service';

export const BLOCK_MODES: BlockMode[] = ['null_ip', 'nxdomain', 'refused'];

interface Form {
  blockMode: BlockMode;
  perClientQps: string;
  retentionDays: string;
  minTtl: string;
  maxTtl: string;
  serveStale: boolean;
  prefetch: boolean;
}

function toForm(s: Settings): Form {
  return {
    blockMode: s.filter.block_mode,
    perClientQps: String(s.limits.per_client_qps),
    retentionDays: String(s.querylog.retention_days),
    minTtl: String(s.cache.min_ttl),
    maxTtl: String(s.cache.max_ttl),
    serveStale: s.cache.serve_stale.enabled,
    prefetch: s.cache.prefetch.enabled,
  };
}

const WHOLE = /^\d{1,10}$/;

/** Client-side check; the server stays the authority and its message is shown as well. */
export function validateForm(f: Form): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const [key, label, value] of [
    ['perClientQps', 'Per-client queries per second', f.perClientQps],
    ['retentionDays', 'Query log retention', f.retentionDays],
    ['minTtl', 'Minimum TTL', f.minTtl],
    ['maxTtl', 'Maximum TTL', f.maxTtl],
  ] as const) {
    if (!WHOLE.test(value.trim())) errors[key] = `${label} must be a whole number.`;
  }
  if (!errors['minTtl'] && !errors['maxTtl'] && Number(f.minTtl) > Number(f.maxTtl)) {
    errors['minTtl'] = 'Minimum TTL cannot exceed the maximum TTL.';
  }
  return errors;
}

/** Runtime settings form. */
@Component({
  selector: 'app-settings-page',
  imports: [MascotErrorComponent, MascotLoadingComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1 class="mb-6 text-2xl font-bold text-cyan">Settings</h1>

    @switch (status()) {
      @case ('loading') {
        <section class="panel" aria-busy="true">
          <dnsy-mascot-loading message="Loading settings..." />
        </section>
      }
      @case ('error') {
        <section class="panel">
          <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="load()" />
        </section>
      }
      @default {
        <form
          class="panel grid grid-cols-1 gap-6 sm:grid-cols-2"
          novalidate
          (submit)="save($event)"
        >
          <fieldset class="sm:col-span-2">
            <legend class="mb-2 text-lg text-cyan">Filtering</legend>
            <label class="field-label" for="set-block">Blocked query response</label>
            <select
              id="set-block"
              class="field-input max-w-xs"
              (change)="patchForm({ blockMode: asMode(val($event)) })"
            >
              @for (m of modes; track m) {
                <option [value]="m" [selected]="m === form().blockMode">{{ m }}</option>
              }
            </select>
          </fieldset>

          <fieldset>
            <legend class="mb-2 text-lg text-cyan">Limits</legend>
            <label class="field-label" for="set-qps">Per-client queries per second (0 = off)</label>
            <input
              id="set-qps"
              class="field-input"
              inputmode="numeric"
              [value]="form().perClientQps"
              [attr.aria-invalid]="errors()['perClientQps'] ? 'true' : null"
              (input)="patchForm({ perClientQps: val($event) })"
            />
            @if (errors()['perClientQps']; as e) {
              <p class="field-error" role="alert">{{ e }}</p>
            }
          </fieldset>

          <fieldset>
            <legend class="mb-2 text-lg text-cyan">Query log</legend>
            <label class="field-label" for="set-ret">Retention (days)</label>
            <input
              id="set-ret"
              class="field-input"
              inputmode="numeric"
              [value]="form().retentionDays"
              [attr.aria-invalid]="errors()['retentionDays'] ? 'true' : null"
              (input)="patchForm({ retentionDays: val($event) })"
            />
            @if (errors()['retentionDays']; as e) {
              <p class="field-error" role="alert">{{ e }}</p>
            }
          </fieldset>

          <fieldset class="sm:col-span-2">
            <legend class="mb-2 text-lg text-cyan">Cache</legend>
            <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label class="field-label" for="set-min">Minimum TTL (seconds)</label>
                <input
                  id="set-min"
                  class="field-input"
                  inputmode="numeric"
                  [value]="form().minTtl"
                  [attr.aria-invalid]="errors()['minTtl'] ? 'true' : null"
                  (input)="patchForm({ minTtl: val($event) })"
                />
                @if (errors()['minTtl']; as e) {
                  <p class="field-error" role="alert">{{ e }}</p>
                }
              </div>
              <div>
                <label class="field-label" for="set-max">Maximum TTL (seconds)</label>
                <input
                  id="set-max"
                  class="field-input"
                  inputmode="numeric"
                  [value]="form().maxTtl"
                  [attr.aria-invalid]="errors()['maxTtl'] ? 'true' : null"
                  (input)="patchForm({ maxTtl: val($event) })"
                />
                @if (errors()['maxTtl']; as e) {
                  <p class="field-error" role="alert">{{ e }}</p>
                }
              </div>
              <label class="flex items-center gap-3 text-sm" for="set-stale">
                <input
                  id="set-stale"
                  type="checkbox"
                  [checked]="form().serveStale"
                  (change)="patchForm({ serveStale: checked($event) })"
                />
                Serve stale answers while refreshing
              </label>
              <label class="flex items-center gap-3 text-sm" for="set-prefetch">
                <input
                  id="set-prefetch"
                  type="checkbox"
                  [checked]="form().prefetch"
                  (change)="patchForm({ prefetch: checked($event) })"
                />
                Prefetch popular entries before they expire
              </label>
            </div>
          </fieldset>

          <div class="flex flex-wrap items-center gap-4 sm:col-span-2">
            <button class="btn" type="submit" [disabled]="busy()">Save settings</button>
            @if (saved()) {
              <span class="text-sm text-secure" role="status">Settings saved.</span>
            }
          </div>
          @if (serverError(); as e) {
            <p class="field-error sm:col-span-2" role="alert">{{ e }}</p>
          }
        </form>
      }
    }
  `,
})
export class SettingsPage {
  private readonly svc = inject(SettingsService);

  protected readonly modes = BLOCK_MODES;
  protected readonly form = signal<Form>({
    blockMode: 'null_ip',
    perClientQps: '0',
    retentionDays: '0',
    minTtl: '0',
    maxTtl: '0',
    serveStale: false,
    prefetch: false,
  });
  protected readonly errors = signal<Record<string, string>>({});
  protected readonly status = signal<'loading' | 'ready' | 'error'>('loading');
  protected readonly loadError = signal('Could not load settings.');
  protected readonly busy = signal(false);
  protected readonly saved = signal(false);
  protected readonly serverError = signal<string | null>(null);

  constructor() {
    this.load();
  }

  protected val(e: Event): string {
    return (e.target as HTMLInputElement).value;
  }

  protected checked(e: Event): boolean {
    return (e.target as HTMLInputElement).checked;
  }

  protected asMode(v: string): BlockMode {
    return BLOCK_MODES.find((m) => m === v) ?? 'null_ip';
  }

  protected patchForm(change: Partial<Form>): void {
    this.saved.set(false);
    this.form.update((f) => ({ ...f, ...change }));
  }

  protected load(): void {
    this.status.set('loading');
    this.svc.get().subscribe({
      next: (s) => {
        this.form.set(toForm(s));
        this.status.set('ready');
      },
      error: (e: unknown) => {
        this.loadError.set(messageOf(e, 'Could not load settings.'));
        this.status.set('error');
      },
    });
  }

  protected save(event: Event): void {
    event.preventDefault();
    this.saved.set(false);
    this.serverError.set(null);
    const f = this.form();
    const errors = validateForm(f);
    this.errors.set(errors);
    if (Object.keys(errors).length > 0) return;
    this.busy.set(true);
    this.svc
      .patch({
        filter: { block_mode: f.blockMode },
        limits: { per_client_qps: Number(f.perClientQps) },
        querylog: { retention_days: Number(f.retentionDays) },
        cache: {
          min_ttl: Number(f.minTtl),
          max_ttl: Number(f.maxTtl),
          serve_stale: { enabled: f.serveStale },
          prefetch: { enabled: f.prefetch },
        },
      })
      .subscribe({
        next: (s) => {
          this.busy.set(false);
          this.form.set(toForm(s));
          this.saved.set(true);
        },
        error: (e: unknown) => {
          this.busy.set(false);
          this.serverError.set(messageOf(e, 'Could not save the settings.'));
        },
      });
  }
}
