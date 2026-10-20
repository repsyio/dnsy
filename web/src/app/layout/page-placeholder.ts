import { ChangeDetectionStrategy, Component, input } from '@angular/core';

/** Stand-in body for pages that later stories fill in. */
@Component({
  selector: 'app-page-placeholder',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1 class="mb-6 text-2xl font-bold text-cyan">{{ heading() }}</h1>
    <section class="panel flex items-center gap-6">
      <img src="mascot/nox-empty.svg" alt="" class="h-24 w-24" />
      <p class="text-muted">This page is under construction.</p>
    </section>
  `,
})
export class PagePlaceholder {
  readonly heading = input.required<string>();
}
