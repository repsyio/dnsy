import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
} from '../../shared/mascot';
import { messageOf } from '../admin-shared/util';
import { ConfirmDialog } from '../zones/confirm-dialog';
import { UpstreamsService } from './upstreams.service';
import type { Group, Health, Strategy } from './upstreams.service';

export const STRATEGIES: Strategy[] = ['round_robin', 'weighted', 'lowest_latency', 'failover'];

type Pending =
  | { type: 'group'; group: Group }
  | { type: 'member'; group: Group; index: number; upstream: string };

/** Upstream groups: strategy, members and live health. */
@Component({
  selector: 'app-upstreams-page',
  imports: [ConfirmDialog, MascotEmptyComponent, MascotErrorComponent, MascotLoadingComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1 class="mb-6 text-2xl font-bold text-cyan">Upstreams</h1>

    @if (actionError(); as e) {
      <p class="field-error mb-4" role="alert">{{ e }}</p>
    }

    @switch (status()) {
      @case ('loading') {
        <section class="panel" aria-busy="true">
          <dnsy-mascot-loading message="Loading upstream groups..." />
        </section>
      }
      @case ('error') {
        <section class="panel">
          <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="load()" />
        </section>
      }
      @default {
        <section class="panel mb-6" aria-labelledby="ng-h">
          <h2 id="ng-h" class="mb-4 text-lg text-cyan">New group</h2>
          <form class="grid grid-cols-1 gap-3 sm:grid-cols-6" novalidate (submit)="create($event)">
            <div class="sm:col-span-2">
              <label class="field-label" for="grp-name">Name</label>
              <input
                id="grp-name"
                class="field-input"
                autocomplete="off"
                [value]="newName()"
                (input)="newName.set(val($event))"
              />
            </div>
            <div class="sm:col-span-2">
              <label class="field-label" for="grp-first">First upstream</label>
              <input
                id="grp-first"
                class="field-input"
                placeholder="1.1.1.1:53 or tls://dns.example"
                autocomplete="off"
                [value]="newMember()"
                (input)="newMember.set(val($event))"
              />
            </div>
            <div>
              <label class="field-label" for="grp-strategy">Strategy</label>
              <select
                id="grp-strategy"
                class="field-input"
                (change)="newStrategy.set(asStrategy(val($event)))"
              >
                @for (s of strategies; track s) {
                  <option [value]="s" [selected]="s === newStrategy()">{{ s }}</option>
                }
              </select>
            </div>
            <div class="flex items-end">
              <button class="btn w-full" type="submit" [disabled]="busy()">Create</button>
            </div>
          </form>
          @if (createError(); as e) {
            <p class="field-error mt-2" role="alert">{{ e }}</p>
          }
        </section>

        @if (groups().length === 0) {
          <section class="panel"><dnsy-mascot-empty message="No upstream groups." /></section>
        }
        @for (g of groups(); track g.name) {
          <section class="panel mb-6" [attr.aria-labelledby]="'g-' + g.name">
            <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
              <h2 [id]="'g-' + g.name" class="text-lg text-cyan">
                {{ g.name }}
                @if (g.default) {
                  <span class="badge badge-ok ml-2">default</span>
                }
              </h2>
              <div class="flex flex-wrap items-end gap-3">
                <div>
                  <label class="field-label" [for]="'st-' + g.name">Strategy</label>
                  <select
                    [id]="'st-' + g.name"
                    class="field-input"
                    (change)="setStrategy(g, asStrategy(val($event)))"
                  >
                    @for (s of strategies; track s) {
                      <option [value]="s" [selected]="s === g.strategy">{{ s }}</option>
                    }
                  </select>
                </div>
                <button
                  class="btn btn-danger"
                  type="button"
                  [attr.aria-label]="'Delete group ' + g.name"
                  (click)="pending.set({ type: 'group', group: g })"
                >
                  Delete group
                </button>
              </div>
            </div>
            @if (g.domains.length > 0) {
              <p class="mb-3 text-xs text-muted">Domains: {{ g.domains.join(', ') }}</p>
            }
            @if (g.members.length === 0) {
              <dnsy-mascot-empty size="sm" message="No members in this group." />
            } @else {
              <div class="overflow-x-auto">
                <table class="w-full text-left text-sm">
                  <caption class="sr-only">
                    Members of
                    {{
                      g.name
                    }}
                  </caption>
                  <thead class="text-xs uppercase tracking-wider text-muted">
                    <tr>
                      <th scope="col" class="py-2 pr-4">Upstream</th>
                      <th scope="col" class="py-2 pr-4">Weight</th>
                      <th scope="col" class="py-2 pr-4">Health</th>
                      <th scope="col" class="py-2"><span class="sr-only">Remove</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    @for (m of g.members; track m.index) {
                      <tr class="border-t border-cyan/20">
                        <td class="py-2 pr-4 break-all">{{ m.upstream }}</td>
                        <td class="py-2 pr-4">{{ m.weight }}</td>
                        <td class="py-2 pr-4">
                          @if (healthOf(g.name, m.upstream); as h) {
                            <span
                              class="badge"
                              [class.badge-ok]="h.available"
                              [class.badge-warn]="!h.available"
                              >{{ h.available ? 'up' : 'down' }}</span
                            >
                            <span class="ml-2 text-xs text-muted">
                              @if (h.latency_ms !== undefined && h.latency_ms !== null) {
                                {{ h.latency_ms }} ms
                              }
                              @if (h.consecutive_failures > 0) {
                                , {{ h.consecutive_failures }} failures
                              }
                            </span>
                          } @else {
                            <span class="text-xs text-muted">unknown</span>
                          }
                        </td>
                        <td class="py-2">
                          <button
                            class="btn btn-danger"
                            type="button"
                            [attr.aria-label]="'Remove ' + m.upstream + ' from ' + g.name"
                            (click)="
                              pending.set({
                                type: 'member',
                                group: g,
                                index: m.index,
                                upstream: m.upstream,
                              })
                            "
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
            <form
              class="mt-4 flex flex-wrap items-end gap-3"
              novalidate
              (submit)="addMember($event, g)"
            >
              <div>
                <label class="field-label" [for]="'am-' + g.name">Add upstream</label>
                <input
                  [id]="'am-' + g.name"
                  class="field-input"
                  autocomplete="off"
                  [value]="memberDraft(g.name)"
                  (input)="setDraft(g.name, val($event))"
                />
              </div>
              <button class="btn" type="submit" [disabled]="busy()">Add member</button>
            </form>
            @if (memberErrors()[g.name]; as e) {
              <p class="field-error" role="alert">{{ e }}</p>
            }
          </section>
        }
      }
    }

    @if (pending(); as p) {
      <app-confirm-dialog
        [heading]="p.type === 'group' ? 'Delete upstream group' : 'Remove upstream'"
        [message]="
          p.type === 'group'
            ? 'Delete group ' + p.group.name + ' and its members?'
            : 'Remove ' + p.upstream + ' from ' + p.group.name + '?'
        "
        [confirmLabel]="p.type === 'group' ? 'Delete' : 'Remove'"
        [busy]="busy()"
        (confirmed)="confirm(p)"
        (cancelled)="pending.set(null)"
      />
    }
  `,
})
export class UpstreamsPage {
  private readonly svc = inject(UpstreamsService);

  protected readonly strategies = STRATEGIES;
  protected readonly groups = signal<Group[]>([]);
  protected readonly health = signal<Record<string, Health[]>>({});
  protected readonly status = signal<'loading' | 'ready' | 'error'>('loading');
  protected readonly loadError = signal('Could not load upstream groups.');
  protected readonly busy = signal(false);
  protected readonly actionError = signal<string | null>(null);
  protected readonly createError = signal<string | null>(null);
  protected readonly pending = signal<Pending | null>(null);
  protected readonly newName = signal('');
  protected readonly newMember = signal('');
  protected readonly newStrategy = signal<Strategy>('round_robin');
  protected readonly drafts = signal<Record<string, string>>({});
  protected readonly memberErrors = signal<Record<string, string>>({});

  constructor() {
    this.load();
  }

  protected val(e: Event): string {
    return (e.target as HTMLInputElement).value;
  }

  protected asStrategy(v: string): Strategy {
    return STRATEGIES.find((s) => s === v) ?? 'round_robin';
  }

  protected healthOf(group: string, upstream: string): Health | undefined {
    return this.health()[group]?.find((h) => h.upstream === upstream);
  }

  protected memberDraft(group: string): string {
    return this.drafts()[group] ?? '';
  }

  protected setDraft(group: string, value: string): void {
    this.drafts.update((d) => ({ ...d, [group]: value }));
  }

  protected load(): void {
    this.status.set('loading');
    this.svc.groups().subscribe({
      next: (groups) => {
        this.groups.set(groups);
        this.status.set('ready');
        for (const g of groups) this.loadHealth(g.name);
      },
      error: (e: unknown) => {
        this.loadError.set(messageOf(e, 'Could not load upstream groups.'));
        this.status.set('error');
      },
    });
  }

  /** Health is best effort: a 503 (resolver not running) leaves the members as "unknown". */
  private loadHealth(name: string): void {
    this.svc.health(name).subscribe({
      next: (h) => this.health.update((all) => ({ ...all, [name]: h })),
      error: () => this.health.update((all) => ({ ...all, [name]: [] })),
    });
  }

  private replace(g: Group): void {
    this.groups.update((all) => all.map((x) => (x.name === g.name ? g : x)));
    this.loadHealth(g.name);
  }

  protected create(event: Event): void {
    event.preventDefault();
    const name = this.newName().trim();
    const upstream = this.newMember().trim();
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(name)) {
      this.createError.set('Name is 1 to 64 characters of letters, digits, ".", "_" or "-".');
      return;
    }
    if (!upstream) {
      this.createError.set('Add at least one upstream.');
      return;
    }
    this.createError.set(null);
    this.busy.set(true);
    this.svc.create({ name, strategy: this.newStrategy(), members: [{ upstream }] }).subscribe({
      next: (g) => {
        this.busy.set(false);
        this.groups.update((all) => [...all, g]);
        this.loadHealth(g.name);
        this.newName.set('');
        this.newMember.set('');
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.createError.set(messageOf(e, 'Could not create the group.'));
      },
    });
  }

  protected setStrategy(g: Group, strategy: Strategy): void {
    if (strategy === g.strategy) return;
    this.actionError.set(null);
    this.svc
      .update(g.name, {
        strategy,
        default: g.default,
        domains: g.domains,
        members: g.members.map((m) => ({ upstream: m.upstream, weight: m.weight })),
      })
      .subscribe({
        next: (u) => this.replace(u),
        error: (e: unknown) => {
          this.actionError.set(messageOf(e, 'Could not change the strategy.'));
          this.groups.update((all) => [...all]);
        },
      });
  }

  protected addMember(event: Event, g: Group): void {
    event.preventDefault();
    const upstream = this.memberDraft(g.name).trim();
    if (!upstream) {
      this.memberErrors.update((m) => ({ ...m, [g.name]: 'Enter an upstream address.' }));
      return;
    }
    this.memberErrors.update((m) => ({ ...m, [g.name]: '' }));
    this.busy.set(true);
    this.svc.addMember(g.name, { upstream }).subscribe({
      next: (u) => {
        this.busy.set(false);
        this.setDraft(g.name, '');
        this.replace(u);
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.memberErrors.update((m) => ({
          ...m,
          [g.name]: messageOf(e, 'Could not add the upstream.'),
        }));
      },
    });
  }

  protected confirm(p: Pending): void {
    this.busy.set(true);
    const fail = (e: unknown): void => {
      this.busy.set(false);
      this.pending.set(null);
      this.actionError.set(messageOf(e, 'Could not complete the change.'));
    };
    if (p.type === 'group') {
      this.svc.remove(p.group.name).subscribe({
        next: () => {
          this.busy.set(false);
          this.pending.set(null);
          this.groups.update((all) => all.filter((x) => x.name !== p.group.name));
        },
        error: fail,
      });
    } else {
      this.svc.removeMember(p.group.name, p.index).subscribe({
        next: (u) => {
          this.busy.set(false);
          this.pending.set(null);
          this.replace(u);
        },
        error: fail,
      });
    }
  }
}
