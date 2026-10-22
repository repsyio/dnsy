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
    const optional = <T>(o: Observable<T>) => o.pipe(catchError(() => of(null)));
    return forkJoin({
      stats: this.api.get<S['DashboardBody']>('/stats/dashboard', {
        from,
        to: now,
        bucket: range.bucketSecs,
        limit: TOP_LIMIT,
      }),
      cache: optional(this.api.get<S['CacheStatsBody']>('/cache')),
      dnssec: optional(this.api.get<S['DnssecStatus']>('/dnssec/status')),
      groups: optional(this.api.get<S['GroupView'][]>('/upstream-groups')),
    }).pipe(
      map(({ stats, cache, dnssec, groups }) => {
        const health = groups?.flatMap((g) => g.health ?? []);
        return {
          summary: stats.summary,
          series: stats.series,
          topDomains: stats.top_domains,
          topBlocked: stats.top_blocked,
          topClients: stats.top_clients,
          cache,
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
