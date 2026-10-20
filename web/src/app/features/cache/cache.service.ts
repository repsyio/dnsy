import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import type { components } from '../../api/schema';
import { ApiService } from '../../core/api.service';

type Schemas = components['schemas'];
export type CacheStats = Schemas['CacheStatsBody'];
export type Flushed = Schemas['Flushed'];

/** Cache statistics and flushing. */
@Injectable({ providedIn: 'root' })
export class CacheService {
  private readonly api = inject(ApiService);

  stats(): Observable<CacheStats> {
    return this.api.get('/cache');
  }
  flushAll(): Observable<Flushed> {
    return this.api.delete('/cache');
  }
  flushName(name: string, subtree: boolean): Observable<Flushed> {
    return this.api.delete('/cache/entries', { name, subtree });
  }
}
