import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import type { components } from '../../api/schema';
import { ApiService } from '../../core/api.service';

type Schemas = components['schemas'];
export type DnssecView = Schemas['DnssecView'];
export type DnssecPolicyInput = Schemas['DnssecPolicyInput'];
export type DsExport = Schemas['DsExport'];
export type DsRecord = Schemas['DsRecordView'];
export type KeyView = Schemas['KeyView'];
export type RolloverRole = Schemas['RolloverRoleView'];
export type ValidationSettings = Schemas['ValidationSettings'];
export type ValidationPatch = Schemas['ValidationPatch'];
export type ValidationMode = Schemas['ValidationMode'];
export type TrustAnchor = Schemas['TrustAnchorView'];
export type DnssecStatus = Schemas['DnssecStatus'];

/** Zone signing policy, keys, DS export, and run-time validation settings. */
@Injectable({ providedIn: 'root' })
export class DnssecService {
  private readonly api = inject(ApiService);

  private path(zone: string, rest = ''): string {
    return `/zones/${encodeURIComponent(zone)}/dnssec${rest}`;
  }

  view(zone: string): Observable<DnssecView> {
    return this.api.get(this.path(zone));
  }
  setPolicy(zone: string, body: DnssecPolicyInput): Observable<DnssecView> {
    return this.api.put(this.path(zone), body);
  }
  ds(zone: string): Observable<DsExport> {
    return this.api.get(this.path(zone, '/ds'));
  }
  rollover(zone: string, keyId: number, algorithm?: number): Observable<unknown> {
    return this.api.post(
      this.path(zone, `/keys/${keyId}/rollover`),
      algorithm ? { algorithm } : {},
    );
  }
  confirmDs(zone: string, keyId: number): Observable<unknown> {
    return this.api.post(this.path(zone, `/keys/${keyId}/ds-confirmed`), {});
  }

  abortRollover(zone: string, role?: string): Observable<DnssecView> {
    return this.api.post(this.path(zone, '/rollover/abort'), role ? { role } : {});
  }

  validation(): Observable<ValidationSettings> {
    return this.api.get('/settings/dnssec');
  }
  patchValidation(body: ValidationPatch): Observable<ValidationSettings> {
    return this.api.patch('/settings/dnssec', body);
  }
  status(): Observable<DnssecStatus> {
    return this.api.get('/dnssec/status');
  }
}
