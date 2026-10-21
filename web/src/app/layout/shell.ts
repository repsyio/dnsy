import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  computed,
  inject,
  signal,
  viewChild,
} from '@angular/core';
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
  { path: '/acl', label: 'ACL' },
  { path: '/client-certs', label: 'Client certs' },
  { path: '/cache', label: 'Cache' },
  { path: '/dnssec', label: 'DNSSEC' },
  { path: '/settings', label: 'Settings' },
  { path: '/tokens', label: 'Tokens' },
  { path: '/profile', label: 'Profile' },
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
  host: { '(document:keydown.escape)': 'closeMenu(true)' },
  template: `
    <div class="flex min-h-screen">
      @if (menuOpen()) {
        <button
          type="button"
          class="fixed inset-0 z-30 bg-bg/80 md:hidden"
          tabindex="-1"
          aria-label="Close menu"
          (click)="closeMenu(false)"
        ></button>
      }
      <aside
        id="main-nav"
        class="fixed inset-y-0 left-0 z-40 w-56 shrink-0 -translate-x-full overflow-y-auto border-r-[0.5px] border-line bg-surface transition-transform invisible md:visible md:static md:translate-x-0 md:bg-surface"
        [class.translate-x-0]="menuOpen()"
        [class.visible]="menuOpen()"
      >
        <nav aria-label="Main" class="py-4">
          @for (item of nav(); track item.path) {
            <a
              class="nav-link"
              [routerLink]="item.path"
              (click)="closeMenu(false)"
              routerLinkActive="nav-link-active"
              ariaCurrentWhenActive="page"
              >{{ item.label }}</a
            >
          }
        </nav>
      </aside>
      <div class="flex min-w-0 flex-1 flex-col">
        <header
          class="flex items-center justify-between gap-2 border-b-[0.5px] border-line bg-surface px-4 py-3 md:px-6"
        >
          <button
            #menuButton
            class="btn md:hidden"
            type="button"
            aria-controls="main-nav"
            [attr.aria-expanded]="menuOpen()"
            (click)="toggleMenu()"
          >
            Menu
          </button>
          <a routerLink="/dashboard" class="flex items-center gap-3">
            <img src="mark.svg" alt="" class="h-9 w-9" />
            <span class="wordmark text-lg">DNSY</span>
          </a>
          <div class="flex items-center gap-4 text-sm">
            @if (auth.user(); as user) {
              <span class="hidden text-muted sm:inline">{{ user.username }} ({{ user.role }})</span>
            }
            <button class="btn" type="button" (click)="logout()">Sign out</button>
          </div>
        </header>
        <main class="relative flex-1 overflow-x-clip p-4 md:p-6">
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
  protected readonly nav = computed(() =>
    NAV_ITEMS.filter((i) => i.path !== '/users' || this.auth.user()?.role === 'admin'),
  );
  protected readonly menuOpen = signal(false);
  private readonly menuButton = viewChild<ElementRef<HTMLButtonElement>>('menuButton');
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
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

  protected toggleMenu(): void {
    if (this.menuOpen()) {
      this.closeMenu(true);
      return;
    }
    this.menuOpen.set(true);
    // The drawer becomes visible on the next render; move focus into it then.
    queueMicrotask(() =>
      setTimeout(() => {
        if (this.menuOpen())
          this.host.nativeElement.querySelector<HTMLElement>('#main-nav a')?.focus();
      }),
    );
  }

  /** Close the off-canvas menu; Escape (or the toggle) returns focus to the menu button. */
  protected closeMenu(restoreFocus: boolean): void {
    if (!this.menuOpen()) return;
    this.menuOpen.set(false);
    if (restoreFocus) this.menuButton()?.nativeElement.focus();
  }

  protected async logout(): Promise<void> {
    try {
      await this.auth.logout();
    } finally {
      await this.router.navigate(['/login']);
    }
  }
}
