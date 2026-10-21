import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { ApiError } from '../../core/api-error';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
} from '../../shared/mascot';
import { CreateZoneDialog } from './create-zone-dialog';
import { ZonesService } from './zones.service';
import type { CreateZone, ZoneSummary } from './zones.service';

@Component({
  selector: 'app-zones-list-page',
  imports: [
    RouterLink,
    CreateZoneDialog,
    MascotEmptyComponent,
    MascotErrorComponent,
    MascotLoadingComponent,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="mb-6 flex flex-wrap items-center justify-between gap-3">
      <h1 class="page-title">Zones</h1>
      <button class="btn" type="button" (click)="openCreate()">Create zone</button>
    </div>

    <section class="panel" aria-live="polite" [attr.aria-busy]="status() === 'loading'">
      @switch (status()) {
        @case ('loading') {
          <dnsy-mascot-loading message="Loading zones..." />
        }
        @case ('error') {
          <dnsy-mascot-error [message]="loadError()" action="Retry" (actionClick)="load()" />
        }
        @default {
          @if (zones().length === 0) {
            <dnsy-mascot-empty
              message="No zones yet."
              action="Create zone"
              (actionClick)="openCreate()"
            />
          } @else {
            <div class="overflow-x-auto">
              <table class="w-full text-left text-sm">
                <caption class="sr-only">
                  Zones
                </caption>
                <thead class="text-xs uppercase tracking-wider text-muted">
                  <tr>
                    <th scope="col" class="py-2 pr-4">Zone</th>
                    <th scope="col" class="py-2 pr-4">Serial</th>
                    <th scope="col" class="py-2 pr-4">Records</th>
                    <th scope="col" class="py-2">Status</th>
                  </tr>
                </thead>
                <tbody>
                  @for (z of zones(); track z.name) {
                    <tr class="border-t-[0.5px] border-line">
                      <td class="py-2 pr-4">
                        <a class="text-red underline" [routerLink]="['/zones', z.name]">{{
                          z.name
                        }}</a>
                      </td>
                      <td class="py-2 pr-4">{{ z.serial }}</td>
                      <td class="py-2 pr-4">{{ z.record_count }}</td>
                      <td class="py-2">
                        <div class="flex flex-wrap gap-2">
                          @if (z.dnssec_enabled) {
                            <span class="badge badge-ok">signed</span>
                          }
                          @if (z.load_error) {
                            <span class="badge badge-warn" [title]="z.load_error">load error</span>
                          }
                        </div>
                        @if (z.load_error) {
                          <p class="mt-1 text-xs text-amber">{{ z.load_error }}</p>
                        }
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          }
        }
      }
    </section>

    @if (creating()) {
      <app-create-zone-dialog
        [busy]="busy()"
        [error]="createError()"
        (created)="create($event)"
        (cancelled)="creating.set(false)"
      />
    }
  `,
})
export class ZonesListPage {
  private readonly svc = inject(ZonesService);
  private readonly router = inject(Router);

  protected readonly zones = signal<ZoneSummary[]>([]);
  protected readonly status = signal<'loading' | 'ready' | 'error'>('loading');
  protected readonly loadError = signal('Could not load zones.');
  protected readonly creating = signal(false);
  protected readonly busy = signal(false);
  protected readonly createError = signal<string | null>(null);

  constructor() {
    this.load();
  }

  protected load(): void {
    this.status.set('loading');
    this.svc.list().subscribe({
      next: (zones) => {
        this.zones.set(zones);
        this.status.set('ready');
      },
      error: (e: unknown) => {
        this.loadError.set(e instanceof ApiError ? e.message : 'Could not load zones.');
        this.status.set('error');
      },
    });
  }

  protected openCreate(): void {
    this.createError.set(null);
    this.creating.set(true);
  }

  protected create(body: CreateZone): void {
    this.busy.set(true);
    this.createError.set(null);
    this.svc.create(body).subscribe({
      next: ({ body: zone }) => {
        this.busy.set(false);
        this.creating.set(false);
        void this.router.navigate(['/zones', zone.name]);
      },
      error: (e: unknown) => {
        this.busy.set(false);
        this.createError.set(e instanceof ApiError ? e.message : 'Could not create the zone.');
      },
    });
  }
}
