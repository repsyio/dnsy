import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  afterNextRender,
  inject,
  input,
  output,
} from '@angular/core';
import { DnssecBadge, SourceBadge } from './badges';
import { formatLatency, formatTime, type LogRecord } from './query-log.model';

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select, textarea';

/** Side drawer with every field of one log record. Escape closes, Tab stays inside. */
@Component({
  selector: 'app-row-drawer',
  imports: [DnssecBadge, SourceBadge],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="fixed inset-0 z-50 flex justify-end bg-bg/70">
      <aside
        class="panel h-full w-full max-w-md overflow-y-auto rounded-none"
        role="dialog"
        aria-modal="true"
        aria-labelledby="qlog-drawer-title"
        (keydown)="onKey($event)"
      >
        <div class="mb-4 flex items-start justify-between gap-3">
          <h2 id="qlog-drawer-title" class="break-all section-title">{{ record().qname }}</h2>
          <button class="btn" type="button" (click)="close()">Close</button>
        </div>
        <dl class="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-2 text-sm">
          <dt class="text-muted">Time</dt>
          <dd>{{ time() }}</dd>
          <dt class="text-muted">Client</dt>
          <dd class="break-all">{{ record().client }}</dd>
          <dt class="text-muted">Principal</dt>
          <dd>{{ record().principal ?? 'none' }}</dd>
          <dt class="text-muted">Transport</dt>
          <dd>{{ record().transport }}</dd>
          <dt class="text-muted">Type</dt>
          <dd>{{ record().qtype }}</dd>
          <dt class="text-muted">Response code</dt>
          <dd>{{ record().rcode }}</dd>
          <dt class="text-muted">Answered by</dt>
          <dd><app-source-badge [value]="record().source" /></dd>
          <dt class="text-muted">Upstream / list</dt>
          <dd class="break-all">{{ record().source_detail ?? 'none' }}</dd>
          <dt class="text-muted">Latency</dt>
          <dd>{{ latency() }}</dd>
          <dt class="text-muted">DNSSEC</dt>
          <dd><app-dnssec-badge [value]="record().dnssec" /></dd>
          <dt class="text-muted">Record id</dt>
          <dd>{{ record().id }}</dd>
        </dl>
      </aside>
    </div>
  `,
})
export class RowDrawer {
  readonly record = input.required<LogRecord>();
  readonly closed = output<void>();
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly opener = document.activeElement as HTMLElement | null;

  constructor() {
    afterNextRender(() => this.focusables()[0]?.focus());
  }

  protected time(): string {
    return formatTime(this.record().ts_ms);
  }

  protected latency(): string {
    return formatLatency(this.record().latency_us);
  }

  private focusables(): HTMLElement[] {
    return Array.from(this.host.nativeElement.querySelectorAll<HTMLElement>(FOCUSABLE));
  }

  protected close(): void {
    this.closed.emit();
    this.opener?.focus?.();
  }

  protected onKey(event: KeyboardEvent): void {
    if (event.key === 'Escape') {
      event.stopPropagation();
      this.close();
    } else if (event.key === 'Tab') {
      const items = this.focusables();
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  }
}
