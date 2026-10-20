import { ChangeDetectionStrategy, Component } from '@angular/core';
import { PagePlaceholder } from '../../layout/page-placeholder';

@Component({
  selector: 'app-upstreams-page',
  imports: [PagePlaceholder],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: '<app-page-placeholder heading="Upstreams" />',
})
export class UpstreamsPage {}
