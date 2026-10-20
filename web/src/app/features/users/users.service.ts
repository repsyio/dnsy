import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import type { components } from '../../api/schema';
import { ApiService } from '../../core/api.service';

type Schemas = components['schemas'];
export type UserInfo = Schemas['UserInfo'];
export type CreateUser = Schemas['CreateUser'];

export const ROLES = ['admin', 'operator', 'viewer'] as const;

/** User administration (admin only). */
@Injectable({ providedIn: 'root' })
export class UsersService {
  private readonly api = inject(ApiService);

  list(): Observable<UserInfo[]> {
    return this.api.get('/users');
  }
  create(body: CreateUser): Observable<UserInfo> {
    return this.api.post('/users', body);
  }
  update(id: number, body: Schemas['UpdateUser']): Observable<UserInfo> {
    return this.api.patch(`/users/${id}`, body);
  }
  remove(id: number): Observable<void> {
    return this.api.delete(`/users/${id}`);
  }
}
