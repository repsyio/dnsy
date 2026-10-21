import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import type { Subscription } from 'rxjs';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
} from '../../shared/mascot';
import { CHART, RANGES, buildChart, describeChart, type RangeKey, type RangeSpec } from './chart';
import { DashboardService, type DashboardData } from './dashboard.service';
import { TopList } from './top-list';
import { formatCompact, formatCount, formatLatency, formatRatio, secureRatio } from './format';

export const REFRESH_MS = 30_000;

interface Tile {
  id: string;
  label: string;
  value: string;
  hint?: string;
  tone?: 'normal' | 'secure' | 'bogus';
}

@Component({
  selector: 'app-dashboard-page',
  imports: [MascotEmptyComponent, MascotErrorComponent, MascotLoadingComponent, TopList],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './dashboard.page.html',
})
export class DashboardPage {
  private readonly service = inject(DashboardService);

  protected readonly ranges = RANGES;
  protected readonly chartBox = CHART;
  protected readonly range = signal<RangeSpec>(RANGES[1]);
  protected readonly data = signal<DashboardData | null>(null);
  protected readonly failed = signal(false);
  protected readonly paused = signal(false);
  protected readonly showTable = signal(false);
  protected readonly updatedAt = signal<Date | null>(null);

  protected readonly empty = computed(() => this.data()?.summary.total === 0);
  protected readonly chart = computed(() => {
    const d = this.data();
    return d ? buildChart(d.series, d.from, d.to, d.range.bucketSecs) : null;
  });
  protected readonly chartLabel = computed(() => {
    const c = this.chart();
    return c ? describeChart(c, this.range().label) : '';
  });
  protected readonly tiles = computed<Tile[]>(() => {
    const d = this.data();
    return d ? buildTiles(d) : [];
  });

  protected readonly formatCount = formatCount;
  protected readonly formatCompact = formatCompact;

  private inflight: Subscription | null = null;

  constructor() {
    this.refresh();
    // A tick never stacks on a running load and never fires for a hidden tab; coming back to the
    // tab refreshes once, so the page is current without background polling.
    const timer = setInterval(() => {
      if (!this.paused() && !document.hidden && !this.inflight) this.refresh();
    }, REFRESH_MS);
    const onVisible = () => {
      if (!document.hidden && !this.paused() && !this.inflight) this.refresh();
    };
    document.addEventListener('visibilitychange', onVisible);
    inject(DestroyRef).onDestroy(() => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisible);
      this.inflight?.unsubscribe();
    });
  }

  protected selectRange(key: RangeKey): void {
    const next = RANGES.find((r) => r.key === key);
    if (!next || next === this.range()) return;
    this.range.set(next);
    this.data.set(null);
    this.refresh();
  }

  protected togglePause(): void {
    this.paused.update((p) => !p);
  }

  protected toggleTable(): void {
    this.showTable.update((s) => !s);
  }

  protected refresh(): void {
    const range = this.range();
    this.inflight?.unsubscribe(); // a manual refresh or range change supersedes the running load
    const sub: Subscription = this.service.load(range, Date.now()).subscribe({
      next: (d) => {
        if (range !== this.range()) return;
        this.data.set(d);
        this.failed.set(false);
        this.updatedAt.set(new Date());
      },
      error: () => {
        if (range !== this.range()) return;
        this.failed.set(true);
      },
    });
    this.inflight = sub.closed ? null : sub;
    sub.add(() => {
      if (this.inflight === sub) this.inflight = null;
    });
  }

  protected retry(): void {
    this.failed.set(false);
    this.refresh();
  }

  protected dropped(n: number): string {
    return formatCount(n);
  }

  protected time(ms: number): string {
    return new Date(ms).toLocaleString();
  }
}

function buildTiles(d: DashboardData): Tile[] {
  const s = d.summary;
  const secure = s.dnssec['secure'] ?? 0;
  const bogus = s.dnssec['bogus'] ?? 0;
  const tiles: Tile[] = [
    { id: 'queries', label: 'Queries', value: formatCount(s.total) },
    {
      id: 'blocked',
      label: 'Blocked',
      value: formatRatio(s.total ? s.blocked_ratio : null),
      hint: `${formatCount(s.blocked)} queries`,
    },
    {
      id: 'cache-hit',
      label: 'Cache hit ratio',
      value: formatRatio(s.cache_hits + s.cache_misses ? s.cache_hit_ratio : null),
      hint: `${formatCount(s.stale_answers)} stale answers`,
    },
    {
      id: 'cache-size',
      label: 'Cache entries',
      value: d.cache ? `${formatCount(d.cache.entries)} / ${formatCount(d.cache.capacity)}` : '-',
      hint: d.cache ? undefined : 'cache unavailable',
    },
    { id: 'latency', label: 'Avg latency', value: formatLatency(s.avg_latency_us) },
    {
      id: 'dnssec-secure',
      label: 'DNSSEC secure',
      value: formatRatio(secureRatio(s.dnssec)),
      hint: `${formatCount(secure)} answers`,
      tone: 'secure',
    },
    {
      id: 'dnssec-bogus',
      label: 'DNSSEC bogus',
      value: formatCount(bogus),
      tone: bogus > 0 ? 'bogus' : 'normal',
    },
    {
      id: 'upstreams',
      label: 'Upstream health',
      value: d.upstreams ? `${d.upstreams.available} / ${d.upstreams.total}` : '-',
      hint: d.upstreams ? 'available' : 'unavailable',
      tone: d.upstreams && d.upstreams.available < d.upstreams.total ? 'bogus' : 'normal',
    },
  ];
  return tiles;
}
