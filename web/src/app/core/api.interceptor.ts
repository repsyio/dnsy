import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { ApiError, isProblem } from './api-error';
import { AuthService } from './auth.service';

/** The CSRF cookie is `__Host-` prefixed when the server serves `Secure` cookies. */
export const CSRF_COOKIES = ['__Host-dnsy_csrf', 'dnsy_csrf'];
export const CSRF_HEADER = 'X-CSRF-Token';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const API_PREFIX = '/api/';

export function readCookie(name: string): string | null {
  for (const part of document.cookie.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

export function readCsrfCookie(): string | null {
  for (const name of CSRF_COOKIES) {
    const value = readCookie(name);
    if (value !== null) return value;
  }
  return null;
}

const ANSWERS_401 = ['/auth/login', '/auth/me', '/auth/me/password'];

/**
 * For same-origin API calls: add the double-submit `X-CSRF-Token` header on unsafe methods,
 * map failures to `ApiError` (RFC 9457 problem+json) and drop the session on 401.
 */
export const apiInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.startsWith(API_PREFIX)) return next(req);
  const token = SAFE_METHODS.has(req.method) ? null : readCsrfCookie();
  const outgoing = token ? req.clone({ setHeaders: { [CSRF_HEADER]: token } }) : req;
  const auth = inject(AuthService);
  const router = inject(Router);
  return next(outgoing).pipe(
    catchError((err: unknown) => {
      if (!(err instanceof HttpErrorResponse)) return throwError(() => err);
      const problem = isProblem(err.error) ? err.error : null;
      // A 401 from login, `/auth/me` or the password change is an answer, not an expired session.
      if (err.status === 401 && !ANSWERS_401.some((p) => req.url.endsWith(p))) {
        auth.markSignedOut();
        void router.navigate(['/login']);
      }
      const message = problem?.detail ?? (err.status === 0 ? 'Server unreachable' : err.message);
      return throwError(() => new ApiError(err.status, problem, message));
    }),
  );
};
