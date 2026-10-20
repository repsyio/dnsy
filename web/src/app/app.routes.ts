import { isDevMode } from '@angular/core';
import { Routes } from '@angular/router';
import { authGuard } from './core/auth.guard';
import { adminGuard } from './features/users/admin.guard';

export const routes: Routes = [
  {
    path: 'login',
    title: 'Sign in',
    loadComponent: () => import('./features/login/login.page').then((m) => m.LoginPage),
  },
  {
    path: '',
    canActivate: [authGuard],
    loadComponent: () => import('./layout/shell').then((m) => m.Shell),
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      {
        path: 'dashboard',
        title: 'Dashboard',
        loadComponent: () =>
          import('./features/dashboard/dashboard.page').then((m) => m.DashboardPage),
      },
      {
        path: 'zones',
        title: 'Zones',
        loadComponent: () =>
          import('./features/zones/zones-list.page').then((m) => m.ZonesListPage),
      },
      {
        path: 'zones/:name',
        title: 'Zone',
        loadComponent: () =>
          import('./features/zones/zone-detail.page').then((m) => m.ZoneDetailPage),
      },
      {
        path: 'filtering',
        title: 'Filtering',
        loadComponent: () =>
          import('./features/filtering/filtering.page').then((m) => m.FilteringPage),
      },
      {
        path: 'upstreams',
        title: 'Upstreams',
        loadComponent: () =>
          import('./features/upstreams/upstreams.page').then((m) => m.UpstreamsPage),
      },
      {
        path: 'query-log',
        title: 'Query log',
        loadComponent: () =>
          import('./features/query-log/query-log.page').then((m) => m.QueryLogPage),
      },
      {
        path: 'users',
        title: 'Users',
        canActivate: [adminGuard],
        loadComponent: () => import('./features/users/users.page').then((m) => m.UsersPage),
      },
      {
        path: 'tokens',
        title: 'API tokens',
        loadComponent: () => import('./features/tokens/tokens.page').then((m) => m.TokensPage),
      },
      {
        path: 'profile',
        title: 'Profile',
        loadComponent: () => import('./features/profile/profile.page').then((m) => m.ProfilePage),
      },
      {
        path: 'settings',
        title: 'Settings',
        loadComponent: () =>
          import('./features/settings/settings.page').then((m) => m.SettingsPage),
      },
      {
        path: 'acl',
        title: 'ACL and rate limits',
        loadComponent: () => import('./features/acl/acl.page').then((m) => m.AclPage),
      },
      {
        path: 'client-certs',
        title: 'Client certificates',
        loadComponent: () => import('./features/certs/certs.page').then((m) => m.CertsPage),
      },
      {
        path: 'dnssec',
        title: 'DNSSEC validation',
        loadComponent: () =>
          import('./features/dnssec/validation.page').then((m) => m.ValidationPage),
      },
      {
        path: 'cache',
        title: 'Cache',
        loadComponent: () => import('./features/cache/cache.page').then((m) => m.CachePage),
      },
      // Component gallery; production builds leave it out, so the path falls through to 404.
      ...(isDevMode()
        ? [
            {
              path: 'dev/mascot',
              title: 'Mascot gallery',
              loadComponent: () =>
                import('./pages/dev/mascot-gallery.page').then((m) => m.MascotGalleryPage),
            },
          ]
        : []),
      {
        path: '**',
        title: 'Not found',
        loadComponent: () => import('./pages/not-found/not-found.page').then((m) => m.NotFoundPage),
      },
    ],
  },
];
