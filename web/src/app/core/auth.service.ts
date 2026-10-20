import { Injectable, computed, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import type { components } from '../api/schema';
import { ApiError } from './api-error';
import { ApiService } from './api.service';

/** Current principal as returned by `GET /api/v1/auth/me`. */
export type Me = components['schemas']['Me'];

/** Cookie-session state. The session cookie is HttpOnly; only `/auth/me` tells us who we are. */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly api = inject(ApiService);
  private readonly current = signal<Me | null>(null);
  private checked = false;

  readonly user = this.current.asReadonly();
  readonly authenticated = computed(() => this.current() !== null);

  /** Ask the server who we are. A 401 means signed out; other errors propagate. */
  async refresh(): Promise<Me | null> {
    try {
      this.current.set(await firstValueFrom(this.api.get<Me>('/auth/me')));
    } catch (e) {
      if (!(e instanceof ApiError) || e.status !== 401) throw e;
      this.current.set(null);
    }
    this.checked = true;
    return this.current();
  }

  /** Resolve the current user, asking the server only once per page load. */
  async ensure(): Promise<Me | null> {
    return this.checked ? this.current() : this.refresh();
  }

  async login(username: string, password: string): Promise<void> {
    await firstValueFrom(
      this.api.post<unknown>('/auth/login', {
        username,
        password,
      } satisfies components['schemas']['Login']),
    );
    await this.refresh();
  }

  async logout(): Promise<void> {
    try {
      await firstValueFrom(this.api.post<unknown>('/auth/logout', {}));
    } finally {
      this.markSignedOut();
    }
  }

  /** Called by the interceptor when any call comes back 401. */
  markSignedOut(): void {
    this.current.set(null);
    this.checked = true;
  }
}
