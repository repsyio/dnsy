import { isDevMode } from '@angular/core';
import { Routes } from '@angular/router';
import { authGuard } from './core/auth.guard';

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
          import('./pages/dashboard/dashboard.page').then((m) => m.DashboardPage),
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
          import('./pages/filtering/filtering.page').then((m) => m.FilteringPage),
      },
      {
        path: 'upstreams',
        title: 'Upstreams',
        loadComponent: () =>
          import('./pages/upstreams/upstreams.page').then((m) => m.UpstreamsPage),
      },
      {
        path: 'query-log',
        title: 'Query log',
        loadComponent: () => import('./pages/query-log/query-log.page').then((m) => m.QueryLogPage),
      },
      {
        path: 'users',
        title: 'Users',
        loadComponent: () => import('./pages/users/users.page').then((m) => m.UsersPage),
      },
      {
        path: 'settings',
        title: 'Settings',
        loadComponent: () => import('./pages/settings/settings.page').then((m) => m.SettingsPage),
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
