import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  inject,
  input,
  signal,
  untracked,
} from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { Observable, map } from 'rxjs';
import { ApiError } from '../../core/api-error';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
  MascotNotFoundComponent,
  MascotSuccessComponent,
} from '../../shared/mascot';
import { ConfirmDialog } from '../../shared/ui/confirm-dialog';
import { ZoneDnssecTab } from './zone-dnssec-tab';
import { RecordEditor } from './record-editor';
import { RECORD_TYPES } from './record-validation';
import type { RecordDraft } from './record-validation';
import { ZonesService } from './zones.service';
import { downloadText } from '../../shared/util/util';
import type { RecordInput, RecordView, ZoneDetail } from './zones.service';

const PAGE_SIZE = 50;

type Status = 'loading' | 'ready' | 'error' | 'notfound';
type Mutation = (etag: string | null) => Observable<string | null>;

interface Conflict {
  retry: () => void;
}

@Component({
  selector: 'app-zone-detail-page',
  imports: [
    RouterLink,
    ConfirmDialog,
    RecordEditor,
    ZoneDnssecTab,
    MascotEmptyComponent,
    MascotErrorComponent,
    MascotLoadingComponent,
    MascotNotFoundComponent,
    MascotSuccessComponent,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p class="mb-2 text-sm"><a class="text-cyan underline" routerLink="/zones">All zones</a></p>

    @switch (status()) {
      @case ('loading') {
        <section class="panel"><dnsy-mascot-loading message="Loading zone..." /></section>
      }
      @case ('notfound') {
        <section class="panel">
          <dnsy-mascot-not-found message="No such zone." />
        </section>
      }
      @case ('error') {
        <section class="panel">
          <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="load()" />
        </section>
      }
      @default {
        @if (zone(); as z) {
          <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
            <h1 class="break-all text-2xl font-bold text-cyan">{{ z.name }}</h1>
            <div class="flex flex-wrap gap-3">
              <button class="btn" type="button" [disabled]="exporting()" (click)="download(false)">
                Download BIND
              </button>
              @if (z.dnssec_enabled) {
                <button class="btn" type="button" [disabled]="exporting()" (click)="download(true)">
                  Download signed
                </button>
              }
              <button class="btn btn-danger" type="button" (click)="confirmDeleteZone.set(true)">
                Delete zone
              </button>
            </div>
          </div>

          <div class="mb-4 flex flex-wrap items-center gap-3 text-sm text-muted">
            <span>{{ z.record_count }} records</span>
            <span>default TTL {{ z.default_ttl }}s</span>
            @if (z.dnssec_enabled) {
              <span class="badge badge-ok">signed</span>
            }
          </div>

          @if (z.load_error) {
            <p class="panel mb-4 border-orange text-sm text-orange" role="alert">
              Zone file not served: {{ z.load_error }}
            </p>
          }

          @if (actionError()) {
            <p class="panel mb-4 border-orange text-sm text-orange" role="alert">
              {{ actionError() }}
            </p>
          }

          @if (conflict(); as c) {
            <div class="panel mb-4 border-orange" role="alert">
              <p class="mb-3 text-sm text-orange">
                This zone was changed elsewhere since you loaded it, so your change was not saved.
              </p>
              <div class="flex flex-wrap gap-3">
                <button class="btn" type="button" (click)="reload()">Reload latest</button>
                <button class="btn btn-danger" type="button" (click)="c.retry()">
                  Overwrite anyway
                </button>
              </div>
            </div>
          }

          <div
            role="tablist"
            aria-label="Zone sections"
            class="mb-4 flex gap-2 border-b border-cyan/30"
          >
            <button
              id="tab-records"
              class="nav-link"
              role="tab"
              type="button"
              [class.nav-link-active]="tab() === 'records'"
              [attr.aria-selected]="tab() === 'records'"
              aria-controls="panel-records"
              (click)="tab.set('records')"
            >
              Records
            </button>
            <button
              id="tab-dnssec"
              class="nav-link"
              role="tab"
              type="button"
              [class.nav-link-active]="tab() === 'dnssec'"
              [attr.aria-selected]="tab() === 'dnssec'"
              aria-controls="panel-dnssec"
              (click)="tab.set('dnssec')"
            >
              DNSSEC
            </button>
          </div>

          @if (tab() === 'dnssec') {
            <section id="panel-dnssec" class="panel" role="tabpanel" aria-labelledby="tab-dnssec">
              <app-zone-dnssec-tab [zone]="name()" (changed)="load(true)" />
            </section>
          }

          <section
            id="panel-records"
            class="panel"
            role="tabpanel"
            aria-labelledby="tab-records"
            [hidden]="tab() !== 'records'"
          >
            <div class="mb-4 flex flex-wrap items-end justify-between gap-3">
              <div>
                <label class="field-label" for="type-filter">Filter by type</label>
                <select
                  id="type-filter"
                  class="field-input"
                  [value]="typeFilter()"
                  (change)="setFilter($event)"
                >
                  <option value="">All</option>
                  @for (t of types; track t) {
                    <option [value]="t" [selected]="t === typeFilter()">{{ t }}</option>
                  }
                </select>
              </div>
              <button class="btn" type="button" (click)="startAdd()">Add record</button>
            </div>

            @if (editing() === 'new') {
              <div class="mb-4 border border-cyan/30 p-4">
                <app-record-editor
                  label="New record"
                  [busy]="busy()"
                  [error]="saveError()"
                  (saved)="saveNew($event)"
                  (cancelled)="cancelEdit()"
                />
              </div>
            }

            @if (records().length === 0 && editing() !== 'new') {
              <dnsy-mascot-empty
                message="No records."
                action="Add record"
                (actionClick)="startAdd()"
              />
            } @else if (records().length > 0) {
              <div class="overflow-x-auto">
                <table class="w-full text-left text-sm">
                  <caption class="sr-only">
                    Records of
                    {{
                      z.name
                    }}
                  </caption>
                  <thead class="text-xs uppercase tracking-wider text-muted">
                    <tr>
                      <th scope="col" class="py-2 pr-4">Name</th>
                      <th scope="col" class="py-2 pr-4">Type</th>
                      <th scope="col" class="py-2 pr-4">TTL</th>
                      <th scope="col" class="py-2 pr-4">Value</th>
                      <th scope="col" class="py-2"><span class="sr-only">Actions</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    @for (r of records(); track r.id) {
                      @if (editing() === r.id) {
                        <tr class="border-t border-cyan/20">
                          <td colspan="5" class="py-3">
                            <app-record-editor
                              [label]="'Edit ' + r.type + ' record ' + r.name"
                              [initial]="draftOf(r)"
                              [busy]="busy()"
                              [error]="saveError()"
                              (saved)="saveEdit(r.id, $event)"
                              (cancelled)="cancelEdit()"
                            />
                          </td>
                        </tr>
                      } @else {
                        <tr class="border-t border-cyan/20">
                          <td class="break-all py-2 pr-4">{{ r.name }}</td>
                          <td class="py-2 pr-4">{{ r.type }}</td>
                          <td class="py-2 pr-4">{{ r.ttl }}</td>
                          <td class="break-all py-2 pr-4">{{ r.value }}</td>
                          <td class="whitespace-nowrap py-2">
                            <button
                              class="mr-3 cursor-pointer text-cyan underline"
                              type="button"
                              [attr.aria-label]="'Edit ' + r.type + ' record ' + r.name"
                              (click)="startEdit(r)"
                            >
                              Edit
                            </button>
                            <button
                              class="cursor-pointer text-orange underline"
                              type="button"
                              [attr.aria-label]="'Delete ' + r.type + ' record ' + r.name"
                              (click)="deleting.set(r)"
                            >
                              Delete
                            </button>
                          </td>
                        </tr>
                      }
                    }
                  </tbody>
                </table>
              </div>
            }

            @if (total() > pageSize) {
              <nav class="mt-4 flex items-center justify-between text-sm" aria-label="Pagination">
                <button class="btn" type="button" [disabled]="offset() === 0" (click)="page(-1)">
                  Previous
                </button>
                <span>{{ offset() + 1 }}-{{ lastShown() }} of {{ total() }}</span>
                <button
                  class="btn"
                  type="button"
                  [disabled]="lastShown() >= total()"
                  (click)="page(1)"
                >
                  Next
                </button>
              </nav>
            }

            @if (notice()) {
              <div class="mt-4" role="status">
                <dnsy-mascot-success size="sm" [message]="notice() ?? ''" />
              </div>
            }
          </section>

          @if (deleting(); as r) {
            <app-confirm-dialog
              heading="Delete record"
              [message]="'Delete the ' + r.type + ' record ' + r.name + ' (' + r.value + ')?'"
              [busy]="busy()"
              [error]="saveError()"
              (confirmed)="deleteRecord(r)"
              (cancelled)="deleting.set(null)"
            />
          }
          @if (confirmDeleteZone()) {
            <app-confirm-dialog
              heading="Delete zone"
              [message]="
                'This permanently deletes ' + z.name + ' and its ' + z.record_count + ' records.'
              "
              [phrase]="z.name"
              [busy]="busy()"
              [error]="saveError()"
              (confirmed)="deleteZone(z)"
              (cancelled)="confirmDeleteZone.set(false)"
            />
          }
        }
      }
    }
  `,
})
export class ZoneDetailPage {
  /** Route parameter `:name`. */
  readonly name = input.required<string>();

  private readonly svc = inject(ZonesService);
  private readonly router = inject(Router);

  protected readonly pageSize = PAGE_SIZE;
  protected readonly types = RECORD_TYPES;
  protected readonly tab = signal<'records' | 'dnssec'>('records');
  protected readonly status = signal<Status>('loading');
  protected readonly loadError = signal('Could not load the zone.');
  protected readonly zone = signal<ZoneDetail | null>(null);
  protected readonly etag = signal<string | null>(null);
  protected readonly records = signal<RecordView[]>([]);
  protected readonly total = signal(0);
  protected readonly offset = signal(0);
  protected readonly typeFilter = signal('');
  protected readonly editing = signal<string | null>(null);
  protected readonly deleting = signal<RecordView | null>(null);
  protected readonly confirmDeleteZone = signal(false);
  protected readonly busy = signal(false);
  protected readonly exporting = signal(false);
  protected readonly saveError = signal<string | null>(null);
  protected readonly actionError = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly conflict = signal<Conflict | null>(null);
  protected readonly lastShown = computed(() => this.offset() + this.records().length);

  constructor() {
    effect(() => {
      this.name();
      untracked(() => {
        this.offset.set(0);
        this.tab.set('records');
        this.typeFilter.set('');
        this.load();
      });
    });
  }

  protected load(silent = false): void {
    if (!silent) this.status.set('loading');
    const name = this.name();
    this.svc.get(name).subscribe({
      next: ({ body, etag }) => {
        this.zone.set(body);
        this.etag.set(etag);
        this.loadRecords(silent);
      },
      error: (e: unknown) => this.fail(e),
    });
  }

  private loadRecords(silent: boolean): void {
    this.svc
      .records(this.name(), {
        limit: PAGE_SIZE,
        offset: this.offset(),
        type: this.typeFilter() || undefined,
      })
      .subscribe({
        next: ({ body, etag }) => {
          this.records.set(body.items);
          this.total.set(body.total);
          if (etag) this.etag.set(etag);
          this.status.set('ready');
        },
        error: (e: unknown) => (silent ? this.actionError.set(msg(e)) : this.fail(e)),
      });
  }

  private fail(e: unknown): void {
    if (e instanceof ApiError && e.status === 404) {
      this.status.set('notfound');
      return;
    }
    this.loadError.set(msg(e, 'Could not load the zone.'));
    this.status.set('error');
  }

  protected reload(): void {
    this.conflict.set(null);
    this.editing.set(null);
    this.deleting.set(null);
    this.confirmDeleteZone.set(false);
    this.saveError.set(null);
    this.load(true);
  }

  protected setFilter(event: Event): void {
    this.typeFilter.set((event.target as HTMLSelectElement).value);
    this.offset.set(0);
    this.loadRecords(true);
  }

  protected page(dir: 1 | -1): void {
    this.offset.update((o) => Math.max(0, o + dir * PAGE_SIZE));
    this.loadRecords(true);
  }

  protected startAdd(): void {
    this.saveError.set(null);
    this.editing.set('new');
  }

  protected startEdit(r: RecordView): void {
    this.saveError.set(null);
    this.editing.set(r.id);
  }

  protected cancelEdit(): void {
    this.editing.set(null);
    this.saveError.set(null);
  }

  protected draftOf(r: RecordView): RecordDraft {
    return { name: r.name, type: r.type, ttl: String(r.ttl), value: r.value };
  }

  protected saveNew(input: RecordInput): void {
    const zone = this.name();
    this.mutate(
      (etag) => this.svc.addRecord(zone, input, etag).pipe(map((t) => t.etag)),
      'Record added.',
    );
  }

  protected saveEdit(id: string, input: RecordInput): void {
    const zone = this.name();
    this.mutate(
      (etag) => this.svc.updateRecord(zone, id, input, etag).pipe(map((t) => t.etag)),
      'Record saved.',
    );
  }

  protected deleteRecord(r: RecordView): void {
    const zone = this.name();
    this.mutate((etag) => this.svc.deleteRecord(zone, r.id, etag), 'Record deleted.');
  }

  protected deleteZone(z: ZoneDetail): void {
    this.mutate(
      (etag) => this.svc.remove(z.name, etag).pipe(map(() => null)),
      null,
      () => void this.router.navigate(['/zones']),
    );
  }

  /** Run a write with `If-Match`; a 412 raises the conflict banner with an overwrite option. */
  private mutate(
    call: Mutation,
    success: string | null,
    done?: () => void,
    etag: string | null = this.etag(),
  ): void {
    this.busy.set(true);
    this.saveError.set(null);
    this.actionError.set(null);
    this.conflict.set(null);
    call(etag).subscribe({
      next: (newTag) => {
        this.busy.set(false);
        this.editing.set(null);
        this.deleting.set(null);
        this.confirmDeleteZone.set(false);
        if (newTag) this.etag.set(newTag);
        if (done) return done();
        this.notice.set(success);
        this.load(true);
      },
      error: (e: unknown) => {
        this.busy.set(false);
        if (e instanceof ApiError && e.status === 412) {
          this.deleting.set(null);
          this.confirmDeleteZone.set(false);
          this.conflict.set({ retry: () => this.mutate(call, success, done, '*') });
        } else {
          this.saveError.set(msg(e, 'The change was rejected.'));
        }
      },
    });
  }

  protected download(signed: boolean): void {
    const name = this.name();
    this.exporting.set(true);
    this.actionError.set(null);
    this.svc.exportZone(name, signed).subscribe({
      next: (text) => {
        this.exporting.set(false);
        const base = name.replace(/\.$/, '') || 'root';
        downloadText(`${base}${signed ? '.signed' : ''}.zone`, text);
      },
      error: (e: unknown) => {
        this.exporting.set(false);
        this.actionError.set(msg(e, 'Export failed.'));
      },
    });
  }
}

function msg(e: unknown, fallback = 'Request failed.'): string {
  return e instanceof ApiError ? e.message : fallback;
}
