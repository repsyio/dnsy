import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
} from '../../shared/mascot';
import { messageOf } from '../../shared/util/util';
import { ConfirmDialog } from '../../shared/ui/confirm-dialog';
import { AclService } from './acl.service';
import type { AclAction, AclOverview, AclRule } from './acl.service';
import { validateCidr } from '../../shared/util/cidr';

const ACTIONS: AclAction[] = ['allow', 'refuse', 'drop'];

/** CIDR allow/deny list (IP blocking) and the per-client rate limit. */
@Component({
  selector: 'app-acl-page',
  imports: [ConfirmDialog, MascotEmptyComponent, MascotErrorComponent, MascotLoadingComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1 class="mb-6 page-title">ACL and rate limits</h1>

    @switch (status()) {
      @case ('loading') {
        <section class="panel" aria-busy="true">
          <dnsy-mascot-loading message="Loading access rules..." />
        </section>
      }
      @case ('error') {
        <section class="panel">
          <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="load()" />
        </section>
      }
      @default {
        <section class="panel mb-6" aria-labelledby="acl-h">
          <h2 id="acl-h" class="mb-1 section-title">Access rules</h2>
          <p class="mb-4 text-sm text-muted">
            Clients matching no rule get the default action:
            <span class="badge badge-ok">{{ defaultAction() }}</span
            >. The first matching rule wins.
          </p>
          <form
            class="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-6"
            novalidate
            (submit)="add($event)"
          >
            <div class="sm:col-span-2">
              <label class="field-label" for="acl-cidr">Address or CIDR</label>
              <input
                id="acl-cidr"
                class="field-input"
                placeholder="192.0.2.0/24"
                autocomplete="off"
                [value]="cidr()"
                [attr.aria-invalid]="cidrError() ? 'true' : null"
                [attr.aria-describedby]="cidrError() ? 'acl-cidr-err' : null"
                (input)="cidr.set(val($event))"
              />
              @if (cidrError(); as e) {
                <p id="acl-cidr-err" class="field-error" role="alert">{{ e }}</p>
              }
            </div>
            <div>
              <label class="field-label" for="acl-action">Action</label>
              <select
                id="acl-action"
                class="field-input"
                (change)="action.set(asAction(val($event)))"
              >
                @for (a of actions; track a) {
                  <option [value]="a" [selected]="a === action()">{{ a }}</option>
                }
              </select>
            </div>
            <div class="sm:col-span-2">
              <label class="field-label" for="acl-comment">Comment</label>
              <input
                id="acl-comment"
                class="field-input"
                maxlength="256"
                autocomplete="off"
                [value]="comment()"
                (input)="comment.set(val($event))"
              />
            </div>
            <div class="flex items-end">
              <button class="btn w-full" type="submit" [disabled]="busy()">Add rule</button>
            </div>
          </form>
          @if (actionError(); as e) {
            <p class="field-error mb-3" role="alert">{{ e }}</p>
          }
          @if (rules().length === 0) {
            <dnsy-mascot-empty message="No access rules." />
          } @else {
            <div class="overflow-x-auto">
              <table class="w-full text-left text-sm">
                <caption class="sr-only">
                  Access rules
                </caption>
                <thead class="text-xs uppercase tracking-wider text-muted">
                  <tr>
                    <th scope="col" class="py-2 pr-4">Match</th>
                    <th scope="col" class="py-2 pr-4">Action</th>
                    <th scope="col" class="py-2 pr-4">Comment</th>
                    <th scope="col" class="py-2"><span class="sr-only">Remove</span></th>
                  </tr>
                </thead>
                <tbody>
                  @for (r of rules(); track r.id) {
                    <tr class="border-t-[0.5px] border-line">
                      <td class="py-2 pr-4 break-all">
                        {{ r.cidr ?? 'cert ' + r.client_cert_sha256 }}
                      </td>
                      <td class="py-2 pr-4">
                        <span
                          class="badge"
                          [class.badge-ok]="r.action === 'allow'"
                          [class.badge-warn]="r.action !== 'allow'"
                          >{{ r.action }}</span
                        >
                      </td>
                      <td class="py-2 pr-4">{{ r.comment }}</td>
                      <td class="py-2">
                        <button
                          class="btn btn-danger"
                          type="button"
                          [attr.aria-label]="'Remove rule ' + (r.cidr ?? r.client_cert_sha256)"
                          (click)="pending.set(r)"
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

        <section class="panel" aria-labelledby="rl-h">
          <h2 id="rl-h" class="mb-1 section-title">Rate limit</h2>
          <p class="mb-4 text-sm text-muted">
            Queries per second allowed from one client; 0 turns the limit off.
          </p>
          <form class="flex flex-wrap items-end gap-3" novalidate (submit)="saveRate($event)">
            <div>
              <label class="field-label" for="rl-qps">Queries per second</label>
              <input
                id="rl-qps"
                class="field-input"
                inputmode="numeric"
                autocomplete="off"
                [value]="qps()"
                [attr.aria-invalid]="rateError() ? 'true' : null"
                (input)="qps.set(val($event))"
              />
            </div>
            <button class="btn" type="submit" [disabled]="busy()">Save</button>
          </form>
          @if (rateError(); as e) {
            <p class="field-error" role="alert">{{ e }}</p>
          }
          @if (rateSaved()) {
            <p class="mt-2 text-sm text-secure" role="status">Rate limit saved.</p>
          }
        </section>
      }
    }

    @if (pending(); as r) {
      <app-confirm-dialog
        heading="Remove access rule"
        [message]="'Remove the rule for ' + (r.cidr ?? r.client_cert_sha256) + '?'"
        confirmLabel="Remove"
        [busy]="busy()"
        (confirmed)="confirmRemove(r)"
        (cancelled)="pending.set(null)"
      />
    }
  `,
})
export class AclPage {
  private readonly svc = inject(AclService);

  protected readonly actions = ACTIONS;
  protected readonly rules = signal<AclRule[]>([]);
  protected readonly defaultAction = signal<AclAction>('allow');
  protected readonly status = signal<'loading' | 'ready' | 'error'>('loading');
  protected readonly loadError = signal('Could not load access rules.');
  protected readonly busy = signal(false);
  protected readonly cidr = signal('');
  protected readonly action = signal<AclAction>('refuse');
  protected readonly comment = signal('');
  protected readonly cidrError = signal<string | null>(null);
  protected readonly actionError = signal<string | null>(null);
  protected readonly pending = signal<AclRule | null>(null);
  protected readonly qps = signal('0');
  protected readonly rateError = signal<string | null>(null);
  protected readonly rateSaved = signal(false);

  constructor() {
    this.load();
  }

  protected val(e: Event): string {
    return (e.target as HTMLInputElement).value;
  }

  protected asAction(v: string): AclAction {
    return ACTIONS.find((a) => a === v) ?? 'refuse';
  }

  protected load(): void {
    this.status.set('loading');
    this.svc.overview().subscribe({
      next: (o: AclOverview) => {
        this.rules.set(o.rules);
        this.defaultAction.set(o.default_action);
        this.qps.set(String(o.rate_limit_qps));
        this.status.set('ready');
      },
      error: (e: unknown) => {
        this.loadError.set(messageOf(e, 'Could not load access rules.'));
        this.status.set('error');
      },
    });
  }

  protected add(event: Event): void {
    event.preventDefault();
    const error = validateCidr(this.cidr());
    this.cidrError.set(error);
    if (error) return;
    this.actionError.set(null);
    this.busy.set(true);
    this.svc
      .add({ cidr: this.cidr().trim(), action: this.action(), comment: this.comment().trim() })
      .subscribe({
        next: (r) => {
          this.busy.set(false);
          this.rules.update((all) => [...all, r]);
          this.cidr.set('');
          this.comment.set('');
        },
        error: (e: unknown) => {
          this.busy.set(false);
          this.actionError.set(messageOf(e, 'Could not add the rule.'));
        },
      });
  }

  protected confirmRemove(r: AclRule): void {
    this.busy.set(true);
    this.svc.remove(r.id).subscribe({
      next: () => {
        this.busy.set(false);
        this.pending.set(null);
        this.rules.update((all) => all.filter((x) => x.id !== r.id));
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.pending.set(null);
        this.actionError.set(messageOf(e, 'Could not remove the rule.'));
      },
    });
  }

  protected saveRate(event: Event): void {
    event.preventDefault();
    this.rateSaved.set(false);
    const text = this.qps().trim();
    if (!/^\d{1,9}$/.test(text)) {
      this.rateError.set('Enter a whole number of queries per second (0 or more).');
      return;
    }
    this.rateError.set(null);
    this.busy.set(true);
    this.svc.setRateLimit(Number(text)).subscribe({
      next: (r) => {
        this.busy.set(false);
        this.qps.set(String(r.qps));
        this.rateSaved.set(true);
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.rateError.set(messageOf(e, 'Could not save the rate limit.'));
      },
    });
  }
}
