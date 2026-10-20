import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import type { components } from '../../api/schema';
import { ApiService } from '../../core/api.service';

type Schemas = components['schemas'];
export type ClientCert = Schemas['ClientCertView'];
export type CreateClientCert = Schemas['CreateClientCert'];

/** DoT client certificate fingerprint allowlist. */
@Injectable({ providedIn: 'root' })
export class CertsService {
  private readonly api = inject(ApiService);

  list(): Observable<ClientCert[]> {
    return this.api.get('/client-certs');
  }
  add(body: CreateClientCert): Observable<ClientCert> {
    return this.api.post('/client-certs', body);
  }
  setEnabled(id: number, enabled: boolean): Observable<ClientCert> {
    return this.api.patch(`/client-certs/${id}`, { enabled });
  }
  remove(id: number): Observable<void> {
    return this.api.delete(`/client-certs/${id}`);
  }
}
