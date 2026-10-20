import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import type { components } from '../../api/schema';
import { formatCount } from './format';

/** Ranked list; the bar is an SVG rect so no inline style is needed under the strict CSP. */
@Component({
  selector: 'app-top-list',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="panel" [attr.aria-labelledby]="headingId()">
      <h2 [id]="headingId()" class="mb-3 text-sm text-cyan">{{ heading() }}</h2>
      @if (rows().length === 0) {
        <p class="text-sm text-muted">No entries in this range.</p>
      } @else {
        <ol class="space-y-2">
          @for (row of rows(); track row.key) {
            <li>
              <div class="flex items-baseline justify-between gap-3 text-sm">
                <span class="min-w-0 truncate" [class.text-orange]="accent() === 'orange'">{{
                  row.key
                }}</span>
                <span class="shrink-0 tabular-nums text-muted">{{ row.label }}</span>
              </div>
              <svg
                viewBox="0 0 100 2"
                preserveAspectRatio="none"
                class="mt-1 h-1 w-full"
                aria-hidden="true"
              >
                <rect x="0" y="0" width="100" height="2" class="fill-cyan/10" />
                <rect
                  x="0"
                  y="0"
                  [attr.width]="row.pct"
                  height="2"
                  [class]="accent() === 'orange' ? 'fill-orange' : 'fill-cyan'"
                />
              </svg>
            </li>
          }
        </ol>
      }
    </section>
  `,
})
export class TopList {
  readonly heading = input.required<string>();
  readonly items = input.required<components['schemas']['TopItem'][]>();
  readonly accent = input<'cyan' | 'orange'>('cyan');

  protected readonly headingId = computed(
    () => 'top-' + this.heading().toLowerCase().replace(/\W+/g, '-'),
  );
  protected readonly rows = computed(() => {
    const items = this.items();
    const max = Math.max(1, ...items.map((i) => i.count));
    return items.map((i) => ({
      key: i.key,
      label: formatCount(i.count),
      pct: Math.max(1, Math.round((i.count / max) * 100)),
    }));
  });
}
