import { ChangeDetectionStrategy, Component } from '@angular/core';
import { PagePlaceholder } from '../../layout/page-placeholder';

@Component({
  selector: 'app-query-log-page',
  imports: [PagePlaceholder],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: '<app-page-placeholder heading="Query log" />',
})
export class QueryLogPage {}
