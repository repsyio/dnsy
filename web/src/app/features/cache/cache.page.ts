import { ChangeDetectionStrategy, Component, DestroyRef, inject, signal } from '@angular/core';
import { MascotErrorComponent, MascotLoadingComponent } from '../../shared/mascot';
import { messageOf } from '../admin-shared/util';
import { ConfirmDialog } from '../zones/confirm-dialog';
import { CacheService } from './cache.service';
import type { CacheStats } from './cache.service';

export const REFRESH_MS = 5000;

/** Live cache statistics with flush-all (confirmed) and flush-by-name. */
@Component({
  selector: 'app-cache-page',
  imports: [ConfirmDialog, MascotErrorComponent, MascotLoadingComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1 class="mb-6 text-2xl font-bold text-cyan">Cache</h1>

    @if (stats(); as s) {
      <section class="panel mb-6" aria-labelledby="cs-h">
        <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
          <h2 id="cs-h" class="text-lg text-cyan">Statistics</h2>
          <span class="text-xs text-muted">Refreshes every 5 seconds</span>
        </div>
        @if (refreshFailed()) {
          <p class="field-error mb-3" role="alert">
            Could not refresh the statistics; showing the last values.
          </p>
        }
        <dl class="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
          @for (item of items(s); track item.label) {
            <div>
              <dt class="text-xs uppercase tracking-wider text-muted">{{ item.label }}</dt>
              <dd class="font-display text-xl text-cyan">{{ item.value }}</dd>
            </div>
          }
        </dl>
      </section>
    } @else if (status() === 'error') {
      <section class="panel mb-6">
        <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="refresh()" />
      </section>
    } @else {
      <section class="panel mb-6" aria-busy="true">
        <dnsy-mascot-loading message="Loading cache statistics..." />
      </section>
    }

    <section class="panel" aria-labelledby="fl-h">
      <h2 id="fl-h" class="mb-4 text-lg text-cyan">Flush</h2>
      <form class="mb-6 flex flex-wrap items-end gap-3" novalidate (submit)="flushName($event)">
        <div>
          <label class="field-label" for="fl-name">Domain name</label>
          <input
            id="fl-name"
            class="field-input"
            placeholder="example.com"
            autocomplete="off"
            [value]="name()"
            [attr.aria-invalid]="nameError() ? 'true' : null"
            (input)="name.set(val($event))"
          />
        </div>
        <label class="flex items-center gap-2 pb-2 text-sm" for="fl-sub">
          <input
            id="fl-sub"
            type="checkbox"
            [checked]="subtree()"
            (change)="subtree.set(checked($event))"
          />
          Include subdomains
        </label>
        <button class="btn" type="submit" [disabled]="busy()">Flush name</button>
      </form>
      @if (nameError(); as e) {
        <p class="field-error mb-3" role="alert">{{ e }}</p>
      }
      <button
        class="btn btn-danger"
        type="button"
        [disabled]="busy()"
        (click)="confirming.set(true)"
      >
        Flush entire cache
      </button>
      @if (result(); as r) {
        <p class="mt-4 text-sm text-secure" role="status">{{ r }}</p>
      }
      @if (flushError(); as e) {
        <p class="field-error mt-4" role="alert">{{ e }}</p>
      }
    </section>

    @if (confirming()) {
      <app-confirm-dialog
        heading="Flush entire cache"
        message="Every cached answer is dropped and the next queries go to the upstreams. Continue?"
        confirmLabel="Flush cache"
        [busy]="busy()"
        (confirmed)="flushAll()"
        (cancelled)="confirming.set(false)"
      />
    }
  `,
})
export class CachePage {
  private readonly svc = inject(CacheService);

  protected readonly stats = signal<CacheStats | null>(null);
  protected readonly status = signal<'loading' | 'ready' | 'error'>('loading');
  protected readonly loadError = signal('Could not load cache statistics.');
  protected readonly refreshFailed = signal(false);
  protected readonly busy = signal(false);
  protected readonly confirming = signal(false);
  protected readonly name = signal('');
  protected readonly subtree = signal(false);
  protected readonly nameError = signal<string | null>(null);
  protected readonly result = signal<string | null>(null);
  protected readonly flushError = signal<string | null>(null);

  constructor() {
    this.refresh();
    const timer = setInterval(() => this.poll(), REFRESH_MS);
    inject(DestroyRef).onDestroy(() => clearInterval(timer));
  }

  protected val(e: Event): string {
    return (e.target as HTMLInputElement).value;
  }

  protected checked(e: Event): boolean {
    return (e.target as HTMLInputElement).checked;
  }

  protected items(s: CacheStats): { label: string; value: string }[] {
    return [
      { label: 'Entries', value: `${s.entries} / ${s.capacity}` },
      { label: 'Hit ratio', value: `${(s.hit_ratio * 100).toFixed(1)}%` },
      { label: 'Hits', value: String(s.hits) },
      { label: 'Misses', value: String(s.misses) },
      { label: 'Inserts', value: String(s.inserts) },
      { label: 'Evictions', value: String(s.evictions) },
      { label: 'Expired', value: String(s.expired) },
      { label: 'Stale served', value: String(s.stale_served) },
      { label: 'Prefetches', value: String(s.prefetches) },
    ];
  }

  protected refresh(): void {
    if (this.stats() === null) this.status.set('loading');
    this.poll();
  }

  private poll(): void {
    this.svc.stats().subscribe({
      next: (s) => {
        this.stats.set(s);
        this.status.set('ready');
        this.refreshFailed.set(false);
      },
      error: (e: unknown) => {
        if (this.stats() === null) {
          this.loadError.set(messageOf(e, 'Could not load cache statistics.'));
          this.status.set('error');
        } else {
          this.refreshFailed.set(true);
        }
      },
    });
  }

  private flushed(removed: number, what: string): void {
    this.busy.set(false);
    this.result.set(`Flushed ${removed} ${removed === 1 ? 'entry' : 'entries'} (${what}).`);
    this.poll();
  }

  private failed(e: unknown): void {
    this.busy.set(false);
    this.flushError.set(messageOf(e, 'Could not flush the cache.'));
  }

  protected flushName(event: Event): void {
    event.preventDefault();
    const name = this.name().trim();
    this.result.set(null);
    this.flushError.set(null);
    if (!name) {
      this.nameError.set('Enter the domain name to flush.');
      return;
    }
    this.nameError.set(null);
    this.busy.set(true);
    this.svc.flushName(name, this.subtree()).subscribe({
      next: (r) => this.flushed(r.removed, name),
      error: (e: unknown) => this.failed(e),
    });
  }

  protected flushAll(): void {
    this.result.set(null);
    this.flushError.set(null);
    this.busy.set(true);
    this.svc.flushAll().subscribe({
      next: (r) => {
        this.confirming.set(false);
        this.flushed(r.removed, 'whole cache');
      },
      error: (e: unknown) => {
        this.confirming.set(false);
        this.failed(e);
      },
    });
  }
}
