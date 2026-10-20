import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import type { components } from '../../api/schema';
import { ApiService } from '../../core/api.service';

type Schemas = components['schemas'];
export type Settings = Schemas['SettingsView'];
export type SettingsPatch = Schemas['SettingsPatch'];
export type BlockMode = Schemas['BlockModeView'];

/** Runtime settings (`GET`/`PATCH /settings`). The API never returns secrets. */
@Injectable({ providedIn: 'root' })
export class SettingsService {
  private readonly api = inject(ApiService);

  get(): Observable<Settings> {
    return this.api.get('/settings');
  }
  patch(body: SettingsPatch): Observable<Settings> {
    return this.api.patch('/settings', body);
  }
}
