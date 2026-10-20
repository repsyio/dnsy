import { ChangeDetectionStrategy, Component } from '@angular/core';
import { PagePlaceholder } from '../../layout/page-placeholder';

@Component({
  selector: 'app-zones-page',
  imports: [PagePlaceholder],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: '<app-page-placeholder heading="Zones" />',
})
export class ZonesPage {}
