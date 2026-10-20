import { Injectable, inject } from '@angular/core';
import { Observable, catchError, forkJoin, map, of } from 'rxjs';
import type { components } from '../../api/schema';
import { ApiService } from '../../core/api.service';
import type { RangeSpec } from './chart';

type S = components['schemas'];

export interface DashboardData {
  range: RangeSpec;
  from: number;
  to: number;
  summary: S['SummaryBody'];
  series: S['SeriesPoint'][];
  topDomains: S['TopItem'][];
  topBlocked: S['TopItem'][];
  topClients: S['TopItem'][];
  /** Optional sources: `null` when the endpoint failed or the feature is off. */
  cache: S['CacheStatsBody'] | null;
  clockTrusted: boolean | null;
  upstreams: { available: number; total: number } | null;
}

const TOP_LIMIT = 10;

@Injectable({ providedIn: 'root' })
export class DashboardService {
  private readonly api = inject(ApiService);

  load(range: RangeSpec, now: number): Observable<DashboardData> {
    const from = now - range.spanMs;
    const q = { from, to: now };
    const top = { ...q, limit: TOP_LIMIT };
    const optional = <T>(o: Observable<T>) => o.pipe(catchError(() => of(null)));
    return forkJoin({
      summary: this.api.get<S['SummaryBody']>('/stats/summary', q),
      series: this.api.get<S['SeriesPoint'][]>('/stats/timeseries', {
        ...q,
        bucket: range.bucketSecs,
      }),
      topDomains: this.api.get<S['TopItem'][]>('/stats/top-domains', top),
      topBlocked: this.api.get<S['TopItem'][]>('/stats/top-blocked', top),
      topClients: this.api.get<S['TopItem'][]>('/stats/top-clients', top),
      cache: optional(this.api.get<S['CacheStatsBody']>('/cache')),
      dnssec: optional(this.api.get<S['DnssecStatus']>('/dnssec/status')),
      groups: optional(this.api.get<S['GroupView'][]>('/upstream-groups')),
    }).pipe(
      map(({ dnssec, groups, ...rest }) => {
        const health = groups?.flatMap((g) => g.health ?? []);
        return {
          ...rest,
          range,
          from,
          to: now,
          clockTrusted: dnssec ? dnssec.clock_trusted : null,
          upstreams: health
            ? { available: health.filter((h) => h.available).length, total: health.length }
            : null,
        };
      }),
    );
  }
}
