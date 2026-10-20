import { ChangeDetectionStrategy, Component } from '@angular/core';
import { PagePlaceholder } from '../../layout/page-placeholder';

@Component({
  selector: 'app-filtering-page',
  imports: [PagePlaceholder],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: '<app-page-placeholder heading="Filtering" />',
})
export class FilteringPage {}
