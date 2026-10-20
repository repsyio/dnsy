import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { MascotEmptyComponent } from '../shared/mascot';

/** Stand-in body for pages that later stories fill in. */
@Component({
  selector: 'app-page-placeholder',
  imports: [MascotEmptyComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1 class="mb-6 text-2xl font-bold text-cyan">{{ heading() }}</h1>
    <section class="panel">
      <dnsy-mascot-empty message="This page is under construction." />
    </section>
  `,
})
export class PagePlaceholder {
  readonly heading = input.required<string>();
}
