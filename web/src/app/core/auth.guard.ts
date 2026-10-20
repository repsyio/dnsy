import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

/** Allow signed-in users; everyone else goes to `/login?redirect=<url>`. */
export const authGuard: CanActivateFn = async (_route, state) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  if (await auth.ensure()) return true;
  return router.createUrlTree(['/login'], { queryParams: { redirect: state.url } });
};
