import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import {
  NavigationCancel,
  NavigationEnd,
  NavigationError,
  NavigationStart,
  Router,
  RouterLink,
  RouterLinkActive,
  RouterOutlet,
} from '@angular/router';
import { filter, fromEvent, map, merge } from 'rxjs';
import { AuthService } from '../core/auth.service';
import { MascotLoadingComponent, MascotOfflineComponent } from '../shared/mascot';

export const NAV_ITEMS = [
  { path: '/dashboard', label: 'Dashboard' },
  { path: '/zones', label: 'Zones' },
  { path: '/filtering', label: 'Filtering' },
  { path: '/upstreams', label: 'Upstreams' },
  { path: '/query-log', label: 'Query log' },
  { path: '/users', label: 'Users' },
  { path: '/settings', label: 'Settings' },
] as const;

@Component({
  selector: 'app-shell',
  imports: [
    MascotLoadingComponent,
    MascotOfflineComponent,
    RouterLink,
    RouterLinkActive,
    RouterOutlet,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="flex min-h-screen">
      <aside class="w-56 shrink-0 border-r border-cyan/40 bg-surface/90 shadow-glow-sm">
        <nav aria-label="Main" class="py-4">
          @for (item of nav; track item.path) {
            <a
              class="nav-link"
              [routerLink]="item.path"
              routerLinkActive="nav-link-active"
              ariaCurrentWhenActive="page"
              >{{ item.label }}</a
            >
          }
        </nav>
      </aside>
      <div class="flex min-w-0 flex-1 flex-col">
        <header
          class="flex items-center justify-between border-b border-cyan/40 bg-surface/90 px-6 py-3"
        >
          <a routerLink="/dashboard" class="flex items-center gap-3">
            <img src="mark.svg" alt="" class="h-9 w-9" />
            <span class="font-display text-xl font-bold tracking-widest text-cyan">DNSY</span>
          </a>
          <div class="flex items-center gap-4 text-sm">
            @if (auth.user(); as user) {
              <span class="text-muted">{{ user.username }} ({{ user.role }})</span>
            }
            <button class="btn" type="button" (click)="logout()">Sign out</button>
          </div>
        </header>
        <main class="flex-1 p-6">
          @if (!online()) {
            <section class="panel mb-6">
              <dnsy-mascot-offline
                size="sm"
                message="You are offline. Changes will not load until the connection returns."
              />
            </section>
          }
          @if (navigating()) {
            <dnsy-mascot-loading size="sm" />
          }
          <router-outlet />
        </main>
      </div>
    </div>
  `,
})
export class Shell {
  protected readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  protected readonly nav = NAV_ITEMS;
  protected readonly navigating = toSignal(
    this.router.events.pipe(
      filter(
        (e) =>
          e instanceof NavigationStart ||
          e instanceof NavigationEnd ||
          e instanceof NavigationCancel ||
          e instanceof NavigationError,
      ),
      map((e) => e instanceof NavigationStart),
    ),
    { initialValue: false },
  );
  protected readonly online = toSignal(
    merge(
      fromEvent(window, 'online').pipe(map(() => true)),
      fromEvent(window, 'offline').pipe(map(() => false)),
    ),
    { initialValue: navigator.onLine },
  );

  protected async logout(): Promise<void> {
    try {
      await this.auth.logout();
    } finally {
      await this.router.navigate(['/login']);
    }
  }
}
