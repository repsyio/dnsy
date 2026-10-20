import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import type { components } from '../../api/schema';
import { ApiService } from '../../core/api.service';

type Schemas = components['schemas'];
export type AclOverview = Schemas['AclOverview'];
export type AclRule = Schemas['AclRuleView'];
export type CreateAclRule = Schemas['CreateAclRule'];
export type AclAction = Schemas['Action'];

/** Client ACL rules and the per-client rate limit. */
@Injectable({ providedIn: 'root' })
export class AclService {
  private readonly api = inject(ApiService);

  overview(): Observable<AclOverview> {
    return this.api.get('/acl');
  }
  add(body: CreateAclRule): Observable<AclRule> {
    return this.api.post('/acl', body);
  }
  remove(id: number): Observable<void> {
    return this.api.delete(`/acl/${id}`);
  }
  setRateLimit(qps: number): Observable<{ qps: number }> {
    return this.api.put('/acl/rate-limit', { qps });
  }
}
