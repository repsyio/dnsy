import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import type { components } from '../../api/schema';
import { ApiService } from '../../core/api.service';

type Schemas = components['schemas'];
export type Blocklist = Schemas['BlocklistView'];
export type CreateBlocklist = Schemas['CreateBlocklist'];
export type RefreshResult = Schemas['RefreshResult'];
export type Rule = Schemas['RuleView'];
export type CreateRule = Schemas['CreateRule'];
export type Format = Schemas['Format'];
export type RuleKind = Schemas['RuleKindView'];

/** Blocklist sources and custom block/allow rules. */
@Injectable({ providedIn: 'root' })
export class FilteringService {
  private readonly api = inject(ApiService);

  blocklists(): Observable<Blocklist[]> {
    return this.api.get('/blocklists');
  }
  addBlocklist(body: CreateBlocklist): Observable<Blocklist> {
    return this.api.post('/blocklists', body);
  }
  setEnabled(id: number, enabled: boolean): Observable<Blocklist> {
    return this.api.patch(`/blocklists/${id}`, { enabled });
  }
  refresh(id: number): Observable<RefreshResult> {
    return this.api.post(`/blocklists/${id}/refresh`, {});
  }
  removeBlocklist(id: number): Observable<void> {
    return this.api.delete(`/blocklists/${id}`);
  }
  rules(): Observable<Rule[]> {
    return this.api.get('/rules');
  }
  addRule(body: CreateRule): Observable<Rule> {
    return this.api.post('/rules', body);
  }
  removeRule(id: number): Observable<void> {
    return this.api.delete(`/rules/${id}`);
  }
}
