import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import type { components } from '../../api/schema';
import { ApiService } from '../../core/api.service';

type Schemas = components['schemas'];
export type TokenInfo = Schemas['TokenInfo'];
export type CreateToken = Schemas['CreateToken'];
export type CreatedToken = Schemas['CreatedToken'];

export const ALL_SCOPES = ['dns:query', 'api:read', 'api:write', 'admin'] as const;

/** Scopes a role may put on a token (mirrors the server's role check). */
export function scopesForRole(role: string): readonly string[] {
  switch (role) {
    case 'admin':
      return ALL_SCOPES;
    case 'operator':
      return ['dns:query', 'api:read', 'api:write'];
    default:
      return ['api:read'];
  }
}

/** The caller's own API tokens. Creating one needs a session; the secret is returned once. */
@Injectable({ providedIn: 'root' })
export class TokensService {
  private readonly api = inject(ApiService);

  list(): Observable<TokenInfo[]> {
    return this.api.get('/tokens');
  }
  create(body: CreateToken): Observable<CreatedToken> {
    return this.api.post('/tokens', body);
  }
  revoke(id: number): Observable<void> {
    return this.api.delete(`/tokens/${id}`);
  }
}
