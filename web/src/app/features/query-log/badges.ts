import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { isDnssecStatus, sourceLabel } from './query-log.model';

/** DNSSEC status: a lock in `--dnsy-secure` for secure, `--dnsy-bogus` for bogus, muted otherwise. */
@Component({
  selector: 'app-dnssec-badge',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <span
      class="badge inline-flex items-center gap-1"
      [class]="classes()"
      [attr.data-status]="status()"
    >
      @if (status() === 'secure') {
        <svg viewBox="0 0 16 16" class="h-3 w-3" fill="currentColor" aria-hidden="true">
          <path d="M5 7V5a3 3 0 0 1 6 0v2h1v7H4V7h1zm1.5 0h3V5a1.5 1.5 0 0 0-3 0v2z" />
        </svg>
      } @else if (status() === 'bogus') {
        <svg viewBox="0 0 16 16" class="h-3 w-3" fill="currentColor" aria-hidden="true">
          <path d="M8 1 0 15h16L8 1zm-.75 5h1.5v4.5h-1.5V6zm0 5.5h1.5V13h-1.5v-1.5z" />
        </svg>
      }
      <span>{{ status() }}</span>
    </span>
  `,
})
export class DnssecBadge {
  readonly value = input.required<string>();
  protected readonly status = computed(() =>
    isDnssecStatus(this.value()) ? this.value() : 'unknown',
  );
  protected readonly classes = computed(() => {
    switch (this.status()) {
      case 'secure':
        return 'border-secure text-secure';
      case 'bogus':
        return 'border-bogus text-bogus';
      case 'indeterminate':
        return 'border-orange text-orange';
      default:
        return 'border-muted text-muted';
    }
  });
}

/** Answer source with its label; stale answers carry an extra tag. */
@Component({
  selector: 'app-source-badge',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: ` <span class="badge" [class]="classes()">{{ label() }}</span> `,
})
export class SourceBadge {
  readonly value = input.required<string>();
  protected readonly label = computed(() => sourceLabel(this.value()));
  protected readonly classes = computed(() => {
    switch (this.value()) {
      case 'blocked':
      case 'refused':
      case 'error':
        return 'border-bogus text-bogus';
      case 'cache_stale':
        return 'border-orange text-orange';
      case 'cache':
        return 'border-secure text-secure';
      default:
        return 'border-cyan text-cyan';
    }
  });
}
