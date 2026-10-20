import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../../core/auth.service';

/** User administration is admin-only; everyone else goes back to the dashboard. */
export const adminGuard: CanActivateFn = async () => {
  const auth = inject(AuthService);
  const router = inject(Router);
  const user = await auth.ensure();
  return user?.role === 'admin' ? true : router.createUrlTree(['/dashboard']);
};
