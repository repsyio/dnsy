import { ChangeDetectionStrategy, Component } from '@angular/core';
import { PagePlaceholder } from '../../layout/page-placeholder';

@Component({
  selector: 'app-settings-page',
  imports: [PagePlaceholder],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: '<app-page-placeholder heading="Settings" />',
})
export class SettingsPage {}
