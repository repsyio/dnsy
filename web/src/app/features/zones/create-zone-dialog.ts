import { ChangeDetectionStrategy, Component, computed, input, output, signal } from '@angular/core';
import { Dialog } from './dialog';
import { validateName } from './record-validation';
import type { CreateZone } from './zones.service';

const NUMERIC = [
  ['defaultTtl', 'Default TTL', 3600],
  ['refresh', 'SOA refresh', 3600],
  ['retry', 'SOA retry', 600],
  ['expire', 'SOA expire', 1209600],
  ['minimum', 'SOA minimum', 300],
] as const;
type NumKey = (typeof NUMERIC)[number][0];

/** Form for a new zone: name, SOA, default TTL and the apex name servers. */
@Component({
  selector: 'app-create-zone-dialog',
  imports: [Dialog],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <app-dialog heading="Create zone" (closed)="cancelled.emit()">
      <form class="grid grid-cols-1 gap-4 sm:grid-cols-2" novalidate (submit)="submit($event)">
        <div class="sm:col-span-2">
          <label class="field-label" for="zone-name">Zone name</label>
          <input
            id="zone-name"
            class="field-input"
            placeholder="example.com."
            autocomplete="off"
            [value]="name()"
            [attr.aria-invalid]="show() && errors().name ? 'true' : null"
            (input)="name.set(val($event))"
          />
          @if (show() && errors().name) {
            <p class="field-error">{{ errors().name }}</p>
          }
        </div>
        <div class="sm:col-span-2">
          <label class="field-label" for="zone-ns">Name servers (one per line, at least one)</label>
          <textarea
            id="zone-ns"
            class="field-input"
            rows="2"
            placeholder="ns1.example.com."
            [value]="ns()"
            (input)="ns.set(val($event))"
          ></textarea>
          @if (show() && errors().ns) {
            <p class="field-error">{{ errors().ns }}</p>
          }
        </div>
        <div>
          <label class="field-label" for="zone-mname">SOA primary server</label>
          <input
            id="zone-mname"
            class="field-input"
            [value]="mname()"
            (input)="mname.set(val($event))"
          />
          @if (show() && errors().mname) {
            <p class="field-error">{{ errors().mname }}</p>
          }
        </div>
        <div>
          <label class="field-label" for="zone-rname">SOA contact (as a name)</label>
          <input
            id="zone-rname"
            class="field-input"
            placeholder="hostmaster.example.com."
            [value]="rname()"
            (input)="rname.set(val($event))"
          />
          @if (show() && errors().rname) {
            <p class="field-error">{{ errors().rname }}</p>
          }
        </div>
        @for (f of numeric; track f.key) {
          <div>
            <label class="field-label" [for]="'zone-' + f.key">{{ f.label }} (seconds)</label>
            <input
              class="field-input"
              inputmode="numeric"
              [id]="'zone-' + f.key"
              [value]="nums()[f.key]"
              (input)="setNum(f.key, val($event))"
            />
            @if (show() && errors()[f.key]) {
              <p class="field-error">{{ errors()[f.key] }}</p>
            }
          </div>
        }
        @if (error()) {
          <p class="field-error sm:col-span-2" role="alert">{{ error() }}</p>
        }
        <div class="flex flex-wrap justify-end gap-3 sm:col-span-2">
          <button class="btn" type="button" (click)="cancelled.emit()">Cancel</button>
          <button class="btn" type="submit" [disabled]="busy()">Create</button>
        </div>
      </form>
    </app-dialog>
  `,
})
export class CreateZoneDialog {
  readonly busy = input(false);
  readonly error = input<string | null>(null);
  readonly created = output<CreateZone>();
  readonly cancelled = output<void>();

  protected readonly numeric = NUMERIC.map(([key, label]) => ({ key, label }));
  protected readonly name = signal('');
  protected readonly ns = signal('');
  protected readonly mname = signal('');
  protected readonly rname = signal('');
  protected readonly nums = signal<Record<NumKey, string>>({
    defaultTtl: '3600',
    refresh: '3600',
    retry: '600',
    expire: '1209600',
    minimum: '300',
  });
  protected readonly show = signal(false);

  protected readonly errors = computed(() => {
    const e: Partial<Record<NumKey | 'name' | 'ns' | 'mname' | 'rname', string>> = {};
    const nameErr = validateName(this.name(), false);
    if (nameErr) e.name = nameErr;
    else if (!this.name().trim().endsWith('.')) e.name = 'Use an absolute name ending in a dot.';
    const servers = this.servers();
    if (servers.length === 0) e.ns = 'At least one name server is required.';
    else if (servers.some((s) => validateName(s, false))) e.ns = 'Invalid name server.';
    if (validateName(this.mname(), false)) e.mname = 'Enter a host name.';
    if (validateName(this.rname(), false)) e.rname = 'Enter a name, e.g. hostmaster.example.com.';
    for (const [key] of NUMERIC) {
      if (!/^\d+$/.test(this.nums()[key]) || Number(this.nums()[key]) > 2_147_483_647) {
        e[key] = 'Whole seconds.';
      }
    }
    return e;
  });

  protected val(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  protected setNum(key: NumKey, value: string): void {
    this.nums.update((n) => ({ ...n, [key]: value }));
  }

  private servers(): string[] {
    return this.ns()
      .split(/[\s,]+/)
      .filter(Boolean);
  }

  protected submit(event: Event): void {
    event.preventDefault();
    this.show.set(true);
    if (Object.keys(this.errors()).length > 0) return;
    const n = this.nums();
    this.created.emit({
      name: this.name().trim(),
      default_ttl: Number(n.defaultTtl),
      soa: {
        mname: this.mname().trim(),
        rname: this.rname().trim(),
        refresh: Number(n.refresh),
        retry: Number(n.retry),
        expire: Number(n.expire),
        minimum: Number(n.minimum),
      },
      records: this.servers().map((value) => ({ name: '@', type: 'NS', value })),
    });
  }
}
