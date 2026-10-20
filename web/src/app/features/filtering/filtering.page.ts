import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { forkJoin } from 'rxjs';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
} from '../../shared/mascot';
import { formatEpoch, messageOf } from '../admin-shared/util';
import { ConfirmDialog } from '../zones/confirm-dialog';
import { FilteringService } from './filtering.service';
import type { Blocklist, Format, Rule, RuleKind } from './filtering.service';

type Pending = { type: 'list'; item: Blocklist } | { type: 'rule'; item: Rule };

const FORMATS: Format[] = ['auto', 'hosts', 'domains', 'adblock'];

/** Blocklist sources (add, enable, refresh, remove) and custom block/allow rules. */
@Component({
  selector: 'app-filtering-page',
  imports: [ConfirmDialog, MascotEmptyComponent, MascotErrorComponent, MascotLoadingComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1 class="mb-6 text-2xl font-bold text-cyan">Filtering</h1>

    @if (notice(); as n) {
      <p class="mb-4 text-sm text-secure" role="status">{{ n }}</p>
    }
    @if (actionError(); as e) {
      <p class="field-error mb-4" role="alert">{{ e }}</p>
    }

    @switch (status()) {
      @case ('loading') {
        <section class="panel" aria-busy="true">
          <dnsy-mascot-loading message="Loading filters..." />
        </section>
      }
      @case ('error') {
        <section class="panel">
          <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="load()" />
        </section>
      }
      @default {
        <section class="panel mb-6" aria-labelledby="lists-h">
          <h2 id="lists-h" class="mb-4 text-lg text-cyan">Blocklist sources</h2>
          <form class="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-6" (submit)="addList($event)">
            <div class="sm:col-span-2">
              <label class="field-label" for="bl-name">Name</label>
              <input
                id="bl-name"
                class="field-input"
                autocomplete="off"
                [value]="listName()"
                (input)="listName.set(val($event))"
              />
            </div>
            <div class="sm:col-span-2">
              <label class="field-label" for="bl-loc">URL or file path</label>
              <input
                id="bl-loc"
                class="field-input"
                autocomplete="off"
                [value]="listLocation()"
                (input)="listLocation.set(val($event))"
              />
            </div>
            <div>
              <label class="field-label" for="bl-fmt">Format</label>
              <select
                id="bl-fmt"
                class="field-input"
                (change)="listFormat.set(asFormat(val($event)))"
              >
                @for (f of formats; track f) {
                  <option [value]="f" [selected]="f === listFormat()">{{ f }}</option>
                }
              </select>
            </div>
            <div class="flex items-end">
              <button class="btn w-full" type="submit" [disabled]="busy()">Add source</button>
            </div>
          </form>
          @if (listError(); as e) {
            <p class="field-error mb-3" role="alert">{{ e }}</p>
          }
          @if (lists().length === 0) {
            <dnsy-mascot-empty message="No blocklist sources yet." />
          } @else {
            <div class="overflow-x-auto">
              <table class="w-full text-left text-sm">
                <caption class="sr-only">
                  Blocklist sources
                </caption>
                <thead class="text-xs uppercase tracking-wider text-muted">
                  <tr>
                    <th scope="col" class="py-2 pr-4">Name</th>
                    <th scope="col" class="py-2 pr-4">Entries</th>
                    <th scope="col" class="py-2 pr-4">Status</th>
                    <th scope="col" class="py-2 pr-4">Last fetched</th>
                    <th scope="col" class="py-2">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  @for (l of lists(); track l.id) {
                    <tr class="border-t border-cyan/20 align-top">
                      <td class="py-2 pr-4">
                        {{ l.name }}
                        <div class="break-all text-xs text-muted">
                          {{ l.location }} ({{ l.format }})
                        </div>
                      </td>
                      <td class="py-2 pr-4">{{ l.entries }}</td>
                      <td class="py-2 pr-4">
                        <span
                          class="badge"
                          [class.badge-ok]="l.enabled"
                          [class.badge-warn]="!l.enabled"
                          >{{ l.enabled ? 'enabled' : 'disabled' }}</span
                        >
                        @if (l.last_status) {
                          <div class="mt-1 text-xs text-muted">{{ l.last_status }}</div>
                        }
                      </td>
                      <td class="py-2 pr-4">{{ fmt(l.last_fetched) }}</td>
                      <td class="py-2">
                        <div class="flex flex-wrap gap-2">
                          <button
                            class="btn"
                            type="button"
                            [attr.aria-label]="(l.enabled ? 'Disable ' : 'Enable ') + l.name"
                            (click)="toggle(l)"
                          >
                            {{ l.enabled ? 'Disable' : 'Enable' }}
                          </button>
                          <button
                            class="btn"
                            type="button"
                            [attr.aria-label]="'Refresh ' + l.name"
                            [disabled]="busy()"
                            (click)="refresh(l)"
                          >
                            Refresh
                          </button>
                          <button
                            class="btn btn-danger"
                            type="button"
                            [attr.aria-label]="'Remove ' + l.name"
                            (click)="pending.set({ type: 'list', item: l })"
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

        <section class="panel" aria-labelledby="rules-h">
          <h2 id="rules-h" class="mb-4 text-lg text-cyan">Custom rules</h2>
          <form class="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-6" (submit)="addRule($event)">
            <div>
              <label class="field-label" for="rule-kind">Action</label>
              <select
                id="rule-kind"
                class="field-input"
                (change)="ruleKind.set(val($event) === 'allow' ? 'allow' : 'block')"
              >
                <option value="block" [selected]="ruleKind() === 'block'">block</option>
                <option value="allow" [selected]="ruleKind() === 'allow'">allow</option>
              </select>
            </div>
            <div class="sm:col-span-4">
              <label class="field-label" for="rule-domain">Domain</label>
              <input
                id="rule-domain"
                class="field-input"
                placeholder="ads.example.com"
                autocomplete="off"
                [value]="ruleDomain()"
                (input)="ruleDomain.set(val($event))"
              />
            </div>
            <div class="flex items-end">
              <button class="btn w-full" type="submit" [disabled]="busy()">Add rule</button>
            </div>
          </form>
          @if (ruleError(); as e) {
            <p class="field-error mb-3" role="alert">{{ e }}</p>
          }
          @if (rules().length === 0) {
            <dnsy-mascot-empty message="No custom rules." />
          } @else {
            <div class="overflow-x-auto">
              <table class="w-full text-left text-sm">
                <caption class="sr-only">
                  Custom rules
                </caption>
                <thead class="text-xs uppercase tracking-wider text-muted">
                  <tr>
                    <th scope="col" class="py-2 pr-4">Action</th>
                    <th scope="col" class="py-2 pr-4">Domain</th>
                    <th scope="col" class="py-2"><span class="sr-only">Remove</span></th>
                  </tr>
                </thead>
                <tbody>
                  @for (r of rules(); track r.id) {
                    <tr class="border-t border-cyan/20">
                      <td class="py-2 pr-4">
                        <span
                          class="badge"
                          [class.badge-ok]="r.kind === 'allow'"
                          [class.badge-warn]="r.kind === 'block'"
                          >{{ r.kind }}</span
                        >
                      </td>
                      <td class="py-2 pr-4 break-all">{{ r.domain }}</td>
                      <td class="py-2">
                        <button
                          class="btn btn-danger"
                          type="button"
                          [attr.aria-label]="'Remove rule ' + r.domain"
                          (click)="pending.set({ type: 'rule', item: r })"
                        >
                          Remove
                        </button>
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

    @if (pending(); as p) {
      <app-confirm-dialog
        [heading]="p.type === 'list' ? 'Remove blocklist source' : 'Remove rule'"
        [message]="
          p.type === 'list'
            ? 'Remove ' + p.item.name + '? Its entries stop blocking.'
            : 'Remove the rule for ' + p.item.domain + '?'
        "
        confirmLabel="Remove"
        [busy]="busy()"
        (confirmed)="confirmRemove(p)"
        (cancelled)="pending.set(null)"
      />
    }
  `,
})
export class FilteringPage {
  private readonly svc = inject(FilteringService);

  protected readonly formats = FORMATS;
  protected readonly lists = signal<Blocklist[]>([]);
  protected readonly rules = signal<Rule[]>([]);
  protected readonly status = signal<'loading' | 'ready' | 'error'>('loading');
  protected readonly loadError = signal('Could not load filters.');
  protected readonly busy = signal(false);
  protected readonly notice = signal<string | null>(null);
  protected readonly actionError = signal<string | null>(null);
  protected readonly listError = signal<string | null>(null);
  protected readonly ruleError = signal<string | null>(null);
  protected readonly pending = signal<Pending | null>(null);
  protected readonly listName = signal('');
  protected readonly listLocation = signal('');
  protected readonly listFormat = signal<Format>('auto');
  protected readonly ruleKind = signal<RuleKind>('block');
  protected readonly ruleDomain = signal('');

  constructor() {
    this.load();
  }

  protected val(e: Event): string {
    return (e.target as HTMLInputElement).value;
  }

  protected asFormat(v: string): Format {
    return FORMATS.find((f) => f === v) ?? 'auto';
  }

  protected fmt(secs: number | null | undefined): string {
    return formatEpoch(secs);
  }

  protected load(): void {
    this.status.set('loading');
    forkJoin({ lists: this.svc.blocklists(), rules: this.svc.rules() }).subscribe({
      next: ({ lists, rules }) => {
        this.lists.set(lists);
        this.rules.set(rules);
        this.status.set('ready');
      },
      error: (e: unknown) => {
        this.loadError.set(messageOf(e, 'Could not load filters.'));
        this.status.set('error');
      },
    });
  }

  protected addList(event: Event): void {
    event.preventDefault();
    const name = this.listName().trim();
    const location = this.listLocation().trim();
    if (!name || !location) {
      this.listError.set('Name and location are required.');
      return;
    }
    this.listError.set(null);
    this.busy.set(true);
    this.svc.addBlocklist({ name, location, format: this.listFormat() }).subscribe({
      next: (l) => {
        this.busy.set(false);
        this.lists.update((all) => [...all, l]);
        this.listName.set('');
        this.listLocation.set('');
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.listError.set(messageOf(e, 'Could not add the source.'));
      },
    });
  }

  protected toggle(l: Blocklist): void {
    this.actionError.set(null);
    this.svc.setEnabled(l.id, !l.enabled).subscribe({
      next: (u) => this.lists.update((all) => all.map((x) => (x.id === u.id ? u : x))),
      error: (e: unknown) => this.actionError.set(messageOf(e, 'Could not update the source.')),
    });
  }

  protected refresh(l: Blocklist): void {
    this.actionError.set(null);
    this.notice.set(null);
    this.busy.set(true);
    this.svc.refresh(l.id).subscribe({
      next: (r) => {
        this.busy.set(false);
        this.notice.set(
          `${l.name}: ${r.outcome}${r.entries != null ? ` (${r.entries} entries)` : ''}`,
        );
        this.svc.blocklists().subscribe({ next: (all) => this.lists.set(all) });
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.actionError.set(messageOf(e, 'Refresh failed.'));
      },
    });
  }

  protected addRule(event: Event): void {
    event.preventDefault();
    const domain = this.ruleDomain().trim();
    if (!domain) {
      this.ruleError.set('Enter a domain.');
      return;
    }
    this.ruleError.set(null);
    this.busy.set(true);
    this.svc.addRule({ kind: this.ruleKind(), domain }).subscribe({
      next: (r) => {
        this.busy.set(false);
        this.rules.update((all) => [...all, r]);
        this.ruleDomain.set('');
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.ruleError.set(messageOf(e, 'Could not add the rule.'));
      },
    });
  }

  protected confirmRemove(p: Pending): void {
    this.busy.set(true);
    const done = {
      next: () => {
        this.busy.set(false);
        this.pending.set(null);
        if (p.type === 'list') this.lists.update((all) => all.filter((x) => x.id !== p.item.id));
        else this.rules.update((all) => all.filter((x) => x.id !== p.item.id));
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.pending.set(null);
        this.actionError.set(messageOf(e, 'Could not remove it.'));
      },
    };
    (p.type === 'list'
      ? this.svc.removeBlocklist(p.item.id)
      : this.svc.removeRule(p.item.id)
    ).subscribe(done);
  }
}
