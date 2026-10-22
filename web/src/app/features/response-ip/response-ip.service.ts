import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import type { components } from '../../api/schema';
import { ApiService } from '../../core/api.service';

export type ResponseIpList = components['schemas']['ResponseIpList'];

/** The response-IP policy: upstream answers inside these networks are blocked. */
@Injectable({ providedIn: 'root' })
export class ResponseIpService {
  private readonly api = inject(ApiService);

  get(): Observable<ResponseIpList> {
    return this.api.get('/response-ip');
  }
  replace(body: ResponseIpList): Observable<ResponseIpList> {
    return this.api.put('/response-ip', body);
  }
}
