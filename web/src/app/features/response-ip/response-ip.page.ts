import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { AuthService } from '../../core/auth.service';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
} from '../../shared/mascot';
import { messageOf } from '../../shared/util/util';
import { validateCidr } from '../../shared/util/cidr';
import { ResponseIpService } from './response-ip.service';

/** Split the textarea into entries: one per line, commas and spaces also separate. */
function entriesOf(text: string): string[] {
  return text.split(/[\s,]+/).filter((e) => e !== '');
}

/** Response-IP policy: networks an upstream answer must not point into (DNS rebinding guard). */
@Component({
  selector: 'app-response-ip-page',
  imports: [MascotEmptyComponent, MascotErrorComponent, MascotLoadingComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1 class="mb-6 page-title">Response IP policy</h1>

    @switch (status()) {
      @case ('loading') {
        <section class="panel" aria-busy="true">
          <dnsy-mascot-loading message="Loading the response IP policy..." />
        </section>
      }
      @case ('error') {
        <section class="panel">
          <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="load()" />
        </section>
      }
      @default {
        <section class="panel" aria-labelledby="rip-h">
          <h2 id="rip-h" class="mb-1 section-title">Blocked response networks</h2>
          <p class="mb-4 text-sm text-muted">
            An upstream answer with an A or AAAA record inside any of these addresses or networks is
            blocked (EDE 15). Changes apply at once; an empty list turns the policy off.
          </p>
          @if (readOnly()) {
            @if (saved().length === 0) {
              <dnsy-mascot-empty message="No response IPs are blocked." />
            } @else {
              <ul class="text-sm" aria-label="Blocked response networks">
                @for (c of saved(); track c) {
                  <li class="border-t-[0.5px] border-line py-2 break-all">{{ c }}</li>
                }
              </ul>
            }
            <p class="mt-4 text-sm text-muted">Your role can view this list but not change it.</p>
          } @else {
            @if (saved().length === 0) {
              <dnsy-mascot-empty message="No response IPs are blocked." />
            }
            <form class="mt-4" novalidate (submit)="save($event)">
              <label class="field-label" for="rip-list">Addresses or CIDRs, one per line</label>
              <textarea
                id="rip-list"
                class="field-input font-mono"
                rows="8"
                placeholder="10.0.0.0/8"
                spellcheck="false"
                autocomplete="off"
                [value]="text()"
                [attr.aria-invalid]="error() ? 'true' : null"
                [attr.aria-describedby]="error() ? 'rip-err' : null"
                (input)="text.set(val($event))"
              ></textarea>
              @if (error(); as e) {
                <p id="rip-err" class="field-error" role="alert">{{ e }}</p>
              }
              <div class="mt-3 flex items-center gap-3">
                <button class="btn" type="submit" [disabled]="busy()">Save</button>
                @if (done()) {
                  <p class="text-sm text-secure" role="status">Response IP policy saved.</p>
                }
              </div>
            </form>
          }
        </section>
      }
    }
  `,
})
export class ResponseIpPage {
  private readonly svc = inject(ResponseIpService);
  private readonly auth = inject(AuthService);

  protected readonly readOnly = computed(() => (this.auth.user()?.role ?? 'viewer') === 'viewer');
  protected readonly status = signal<'loading' | 'ready' | 'error'>('loading');
  protected readonly loadError = signal('Could not load the response IP policy.');
  protected readonly saved = signal<string[]>([]);
  protected readonly text = signal('');
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly done = signal(false);

  constructor() {
    this.load();
  }

  protected val(e: Event): string {
    return (e.target as HTMLTextAreaElement).value;
  }

  protected load(): void {
    this.status.set('loading');
    this.svc.get().subscribe({
      next: (l) => {
        this.apply(l.cidrs);
        this.status.set('ready');
      },
      error: (e: unknown) => {
        this.loadError.set(messageOf(e, 'Could not load the response IP policy.'));
        this.status.set('error');
      },
    });
  }

  protected save(event: Event): void {
    event.preventDefault();
    this.done.set(false);
    const cidrs = entriesOf(this.text());
    for (const c of cidrs) {
      const e = validateCidr(c);
      if (e) {
        this.error.set(`${c}: ${e}`);
        return;
      }
    }
    this.error.set(null);
    this.busy.set(true);
    this.svc.replace({ cidrs }).subscribe({
      next: (l) => {
        this.busy.set(false);
        this.apply(l.cidrs);
        this.done.set(true);
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.error.set(messageOf(e, 'Could not save the response IP policy.'));
      },
    });
  }

  private apply(cidrs: string[]): void {
    this.saved.set(cidrs);
    this.text.set(cidrs.join('\n'));
  }
}
