import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import type { components } from '../../api/schema';
import { ApiService } from '../../core/api.service';

type Schemas = components['schemas'];
export type Group = Schemas['GroupView'];
export type GroupBody = Schemas['GroupBody'];
export type CreateGroup = Schemas['CreateGroup'];
export type Health = Schemas['HealthView'];
export type Strategy = Schemas['StrategyView'];
export type MemberInput = Schemas['MemberInput'];

/** Upstream groups, their members and health. */
@Injectable({ providedIn: 'root' })
export class UpstreamsService {
  private readonly api = inject(ApiService);

  private path(name: string): string {
    return `/upstream-groups/${encodeURIComponent(name)}`;
  }

  groups(): Observable<Group[]> {
    return this.api.get('/upstream-groups');
  }
  health(name: string): Observable<Health[]> {
    return this.api.get(`${this.path(name)}/health`);
  }
  create(body: CreateGroup): Observable<Group> {
    return this.api.post('/upstream-groups', body);
  }
  update(name: string, body: GroupBody): Observable<Group> {
    return this.api.put(this.path(name), body);
  }
  remove(name: string): Observable<void> {
    return this.api.delete(this.path(name));
  }
  addMember(name: string, member: MemberInput): Observable<Group> {
    return this.api.post(`${this.path(name)}/upstreams`, member);
  }
  removeMember(name: string, index: number): Observable<Group> {
    return this.api.delete(`${this.path(name)}/upstreams/${index}`);
  }
}
