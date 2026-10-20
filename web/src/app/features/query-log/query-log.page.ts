import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { ApiError } from '../../core/api-error';
import { AuthService } from '../../core/auth.service';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
} from '../../shared/mascot';
import { DnssecBadge, SourceBadge } from './badges';
import {
  DEFAULT_FILTERS,
  DNSSEC_STATUSES,
  QTYPES,
  RANGES,
  RCODES,
  SOURCES,
  formatLatency,
  formatTime,
  mergeRecords,
  toQuery,
  type Filters,
  type LogRecord,
} from './query-log.model';
import { QueryLogService, type TailState } from './query-log.service';
import { RowDrawer } from './row-drawer';

/** Most rows kept in the table (live tail trims the oldest) and most held while paused. */
export const MAX_ROWS = 1000;
export const PENDING_CAP = 500;

@Component({
  selector: 'app-query-log-page',
  imports: [
    DnssecBadge,
    SourceBadge,
    RowDrawer,
    MascotEmptyComponent,
    MascotErrorComponent,
    MascotLoadingComponent,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
      <h1 class="text-2xl font-bold text-cyan">Query log</h1>
      <div class="flex flex-wrap items-center gap-2">
        @if (tailOn()) {
          <span class="text-xs uppercase tracking-wider text-muted" role="status">{{
            tailLabel()
          }}</span>
          <button class="btn" type="button" [attr.aria-pressed]="paused()" (click)="togglePause()">
            {{ paused() ? 'Resume' : 'Pause' }}
          </button>
        }
        <button
          class="btn"
          type="button"
          [attr.aria-pressed]="tailOn()"
          [disabled]="!canTail()"
          [title]="canTail() ? '' : 'Live tail needs the operator role'"
          (click)="toggleTail()"
        >
          Live tail {{ tailOn() ? 'on' : 'off' }}
        </button>
      </div>
    </div>

    <form
      class="panel mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4"
      (submit)="apply($event)"
    >
      <div>
        <label class="field-label" for="f-range">Time range</label>
        <select
          id="f-range"
          class="field-input"
          [value]="draft().range"
          (change)="set('range', $event)"
        >
          @for (r of ranges; track r.key) {
            <option [value]="r.key" [selected]="draft().range === r.key">{{ r.label }}</option>
          }
          <option value="custom" [selected]="draft().range === 'custom'">Custom</option>
        </select>
      </div>
      @if (draft().range === 'custom') {
        <div>
          <label class="field-label" for="f-from">From</label>
          <input
            id="f-from"
            type="datetime-local"
            class="field-input"
            [value]="draft().customFrom"
            (input)="set('customFrom', $event)"
          />
        </div>
        <div>
          <label class="field-label" for="f-to">To</label>
          <input
            id="f-to"
            type="datetime-local"
            class="field-input"
            [value]="draft().customTo"
            (input)="set('customTo', $event)"
          />
        </div>
      }
      <div>
        <label class="field-label" for="f-domain">Domain contains</label>
        <input
          id="f-domain"
          type="search"
          class="field-input"
          placeholder="example.com"
          autocomplete="off"
          [value]="draft().domain"
          (input)="set('domain', $event)"
        />
      </div>
      <div>
        <label class="field-label" for="f-client">Client</label>
        <input
          id="f-client"
          class="field-input"
          placeholder="192.0.2.10"
          autocomplete="off"
          [value]="draft().client"
          (input)="set('client', $event)"
        />
      </div>
      <div>
        <label class="field-label" for="f-type">Type</label>
        <select id="f-type" class="field-input" (change)="set('qtype', $event)">
          <option value="" [selected]="draft().qtype === ''">Any</option>
          @for (t of qtypes; track t) {
            <option [value]="t" [selected]="draft().qtype === t">{{ t }}</option>
          }
        </select>
      </div>
      <div>
        <label class="field-label" for="f-source">Outcome</label>
        <select id="f-source" class="field-input" (change)="set('source', $event)">
          <option value="" [selected]="draft().source === ''">Any</option>
          @for (s of sources; track s.value) {
            <option [value]="s.value" [selected]="draft().source === s.value">{{ s.label }}</option>
          }
        </select>
      </div>
      <div>
        <label class="field-label" for="f-rcode">Response code</label>
        <select id="f-rcode" class="field-input" (change)="set('rcode', $event)">
          <option value="" [selected]="draft().rcode === ''">Any</option>
          @for (c of rcodes; track c) {
            <option [value]="c" [selected]="draft().rcode === c">{{ c }}</option>
          }
        </select>
      </div>
      <div>
        <label class="field-label" for="f-dnssec">DNSSEC</label>
        <select id="f-dnssec" class="field-input" (change)="set('dnssec', $event)">
          <option value="" [selected]="draft().dnssec === ''">Any</option>
          @for (d of dnssecs; track d) {
            <option [value]="d" [selected]="draft().dnssec === d">{{ d }}</option>
          }
        </select>
      </div>
      <div class="flex items-end gap-2 sm:col-span-2 lg:col-span-4">
        <button class="btn" type="submit">Apply</button>
        <button class="btn" type="button" (click)="reset()">Reset</button>
      </div>
    </form>

    @if (tailOn() && paused() && pending().length > 0) {
      <p class="mb-2 text-sm text-orange" role="status">
        Paused: {{ pending().length }} new
        {{ pending().length === 1 ? 'query' : 'queries' }} waiting.
      </p>
    }
    @if (lagged() > 0) {
      <p class="mb-2 text-sm text-orange" role="status">
        The live tail fell behind {{ lagged() }} {{ lagged() === 1 ? 'time' : 'times' }}; some rows
        were skipped.
      </p>
    }

    <section class="panel" aria-live="polite" [attr.aria-busy]="status() === 'loading'">
      @switch (status()) {
        @case ('loading') {
          <dnsy-mascot-loading message="Loading the query log..." />
        }
        @case ('error') {
          <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="load()" />
        }
        @default {
          @if (records().length === 0) {
            <dnsy-mascot-empty message="No queries match these filters." />
          } @else {
            <div class="overflow-x-auto">
              <table class="w-full text-left text-sm">
                <caption class="sr-only">
                  Query log, newest first
                </caption>
                <thead class="text-xs uppercase tracking-wider text-muted">
                  <tr>
                    <th scope="col" class="py-2 pr-4">Time</th>
                    <th scope="col" class="py-2 pr-4">Domain</th>
                    <th scope="col" class="py-2 pr-4">Type</th>
                    <th scope="col" class="hidden py-2 pr-4 md:table-cell">Client</th>
                    <th scope="col" class="py-2 pr-4">Outcome</th>
                    <th scope="col" class="hidden py-2 pr-4 md:table-cell">Code</th>
                    <th scope="col" class="py-2 pr-4">DNSSEC</th>
                    <th scope="col" class="hidden py-2 text-right lg:table-cell">Latency</th>
                  </tr>
                </thead>
                <tbody>
                  @for (r of records(); track r.id) {
                    <tr class="border-t border-cyan/20">
                      <td class="whitespace-nowrap py-2 pr-4 text-muted">{{ time(r) }}</td>
                      <td class="py-2 pr-4">
                        <button
                          type="button"
                          class="break-all text-left text-cyan underline"
                          [attr.aria-label]="'Details for ' + r.qname"
                          (click)="open(r)"
                        >
                          {{ r.qname }}
                        </button>
                      </td>
                      <td class="py-2 pr-4">{{ r.qtype }}</td>
                      <td class="hidden py-2 pr-4 md:table-cell">{{ r.client }}</td>
                      <td class="py-2 pr-4"><app-source-badge [value]="r.source" /></td>
                      <td class="hidden py-2 pr-4 md:table-cell">{{ r.rcode }}</td>
                      <td class="py-2 pr-4"><app-dnssec-badge [value]="r.dnssec" /></td>
                      <td class="hidden whitespace-nowrap py-2 text-right lg:table-cell">
                        {{ latency(r) }}
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
            <div class="mt-4 flex flex-wrap items-center gap-3">
              @if (nextCursor()) {
                <button class="btn" type="button" [disabled]="loadingMore()" (click)="loadMore()">
                  {{ loadingMore() ? 'Loading...' : 'Load more' }}
                </button>
              } @else {
                <span class="text-xs text-muted">End of the log.</span>
              }
              @if (moreError()) {
                <span class="field-error" role="alert">{{ moreError() }}</span>
              }
            </div>
          }
        }
      }
    </section>

    @if (selected(); as row) {
      <app-row-drawer [record]="row" (closed)="selected.set(null)" />
    }
  `,
})
export class QueryLogPage {
  private readonly svc = inject(QueryLogService);
  private readonly auth = inject(AuthService);

  protected readonly ranges = RANGES;
  protected readonly qtypes = QTYPES;
  protected readonly rcodes = RCODES;
  protected readonly sources = SOURCES;
  protected readonly dnssecs = DNSSEC_STATUSES;

  protected readonly draft = signal<Filters>({ ...DEFAULT_FILTERS });
  private applied: Filters = { ...DEFAULT_FILTERS };

  protected readonly records = signal<LogRecord[]>([]);
  protected readonly nextCursor = signal<string | null>(null);
  protected readonly status = signal<'loading' | 'ready' | 'error'>('loading');
  protected readonly loadError = signal('Could not load the query log.');
  protected readonly loadingMore = signal(false);
  protected readonly moreError = signal<string | null>(null);
  protected readonly selected = signal<LogRecord | null>(null);

  protected readonly tailOn = signal(false);
  protected readonly paused = signal(false);
  protected readonly tailState = signal<TailState>('connecting');
  protected readonly pending = signal<LogRecord[]>([]);
  protected readonly lagged = signal(0);
  protected readonly canTail = computed(() => this.auth.user()?.role !== 'viewer');
  protected readonly tailLabel = computed(() => {
    if (this.paused()) return 'Paused';
    return { connecting: 'Connecting...', live: 'Live', reconnecting: 'Reconnecting...' }[
      this.tailState()
    ];
  });

  private stopTail: (() => void) | null = null;
  private generation = 0;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.stopTail?.());
    this.load();
  }

  protected time(r: LogRecord): string {
    return formatTime(r.ts_ms);
  }

  protected latency(r: LogRecord): string {
    return formatLatency(r.latency_us);
  }

  protected set(key: keyof Filters, event: Event): void {
    const value = (event.target as HTMLInputElement | HTMLSelectElement).value;
    this.draft.update((f) => ({ ...f, [key]: value }));
  }

  protected apply(event?: Event): void {
    event?.preventDefault();
    this.applied = { ...this.draft() };
    this.load();
    if (this.tailOn()) this.startTail();
  }

  protected reset(): void {
    this.draft.set({ ...DEFAULT_FILTERS });
    this.apply();
  }

  protected load(): void {
    const gen = ++this.generation;
    this.status.set('loading');
    this.moreError.set(null);
    this.svc.search(toQuery(this.applied, Date.now())).subscribe({
      next: (page) => {
        if (gen !== this.generation) return;
        this.records.set(page.entries);
        this.nextCursor.set(page.next_cursor ?? null);
        this.pending.set([]);
        this.status.set('ready');
      },
      error: (e: unknown) => {
        if (gen !== this.generation) return;
        this.loadError.set(e instanceof ApiError ? e.message : 'Could not load the query log.');
        this.status.set('error');
      },
    });
  }

  protected loadMore(): void {
    const cursor = this.nextCursor();
    if (!cursor || this.loadingMore()) return;
    const gen = this.generation;
    this.loadingMore.set(true);
    this.moreError.set(null);
    this.svc.search(toQuery(this.applied, Date.now()), cursor).subscribe({
      next: (page) => {
        if (gen !== this.generation) return;
        // Older rows go after the current ones; duplicates (rows the tail already added) drop out.
        const seen = new Set(this.records().map((r) => r.id));
        this.records.update((rows) => [...rows, ...page.entries.filter((r) => !seen.has(r.id))]);
        this.nextCursor.set(page.next_cursor ?? null);
        this.loadingMore.set(false);
      },
      error: (e: unknown) => {
        if (gen !== this.generation) return;
        this.moreError.set(e instanceof ApiError ? e.message : 'Could not load more rows.');
        this.loadingMore.set(false);
      },
    });
  }

  protected open(r: LogRecord): void {
    this.selected.set(r);
  }

  protected toggleTail(): void {
    if (this.tailOn()) {
      this.stopTail?.();
      this.stopTail = null;
      this.tailOn.set(false);
      this.paused.set(false);
      this.pending.set([]);
    } else {
      this.tailOn.set(true);
      this.startTail();
    }
  }

  protected togglePause(): void {
    if (this.paused()) {
      this.records.update((rows) => mergeRecords(rows, this.pending(), MAX_ROWS));
      this.pending.set([]);
      this.paused.set(false);
    } else {
      this.paused.set(true);
    }
  }

  private startTail(): void {
    this.stopTail?.();
    this.lagged.set(0);
    this.stopTail = this.svc.tail(toQuery(this.applied, Date.now(), false), {
      record: (r) => this.onTailRecord(r),
      lagged: () => this.lagged.update((n) => n + 1),
      state: (s) => this.tailState.set(s),
    });
  }

  private onTailRecord(r: LogRecord): void {
    if (this.status() !== 'ready') return;
    if (this.paused()) {
      this.pending.update((p) => mergeRecords(p, [r], PENDING_CAP));
    } else {
      this.records.update((rows) => mergeRecords(rows, [r], MAX_ROWS));
    }
  }
}
