import { type APIRequestContext, type APIResponse, request } from '@playwright/test';
import { PASSWORD } from './server';

/** The cookie jar of a signed-in API context carries the CSRF token for unsafe methods. */
export class Api {
  private constructor(
    private readonly ctx: APIRequestContext,
    readonly baseURL: string,
  ) {}

  /** Log in over the REST API (no browser) and keep the session cookies. */
  static async login(baseURL: string, username: string, password = PASSWORD): Promise<Api> {
    // An empty jar on purpose: the runner would otherwise hand the test's own session cookie to
    // this context, and logging in with a session cookie ends that session.
    const ctx = await request.newContext({ baseURL, storageState: { cookies: [], origins: [] } });
    const res = await ctx.post('/api/v1/auth/login', { data: { username, password } });
    if (!res.ok()) throw new Error(`login ${username} failed: ${res.status()} ${await res.text()}`);
    return new Api(ctx, baseURL);
  }

  /**
   * A client that reuses a session saved earlier (the global setup's), without a login. Logins
   * count against the server's throttle per username and address, in flight included, so many
   * workers logging in as the same user at once would lock that user out.
   */
  static async fromState(baseURL: string, storageState: string): Promise<Api> {
    return new Api(await request.newContext({ baseURL, storageState }), baseURL);
  }

  private async csrf(): Promise<Record<string, string>> {
    const state = await this.ctx.storageState();
    const token = state.cookies.find(
      (c) => c.name === 'dnsy_csrf' || c.name === '__Host-dnsy_csrf',
    )?.value;
    return token ? { 'X-CSRF-Token': token } : {};
  }

  get(path: string): Promise<APIResponse> {
    return this.ctx.get(`/api/v1${path}`);
  }

  async send(
    method: 'post' | 'put' | 'patch' | 'delete',
    path: string,
    data?: unknown,
    headers: Record<string, string> = {},
  ): Promise<APIResponse> {
    return this.ctx.fetch(`/api/v1${path}`, {
      method: method.toUpperCase(),
      data,
      headers: { ...(await this.csrf()), ...headers },
    });
  }

  /** `send` that fails the test setup on a non-2xx answer and returns the JSON body. */
  async ok<T = unknown>(
    method: 'post' | 'put' | 'patch' | 'delete',
    path: string,
    data?: unknown,
  ): Promise<T> {
    const res = await this.send(method, path, data);
    if (!res.ok()) throw new Error(`${method} ${path}: ${res.status()} ${await res.text()}`);
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  dispose(): Promise<void> {
    return this.ctx.dispose();
  }
}
