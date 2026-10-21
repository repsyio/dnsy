import { test as base, expect, type Page } from '@playwright/test';
import { statePath } from './global-setup';
import { Api } from './support/api';
import { DnsyServer, PASSWORD, type ServerInfo, uid } from './support/server';

export { expect, uid, PASSWORD };

export function sharedServer(): ServerInfo {
  const raw = process.env['DNSY_E2E_SERVER'];
  if (!raw) throw new Error('DNSY_E2E_SERVER missing: the global setup did not run');
  return JSON.parse(raw) as ServerInfo;
}

const CSP_MARKERS = [/content security policy/i, /refused to (load|execute|apply|connect|frame)/i];

interface Fixtures {
  /** Violations of the content security policy logged to the console (the test fails on any). */
  cspGuard: void;
  /** Starts a private server (own database, upstream, users); stopped after the test. */
  freshServer: (opts?: { users?: boolean; extraConfig?: string }) => Promise<DnsyServer>;
}

interface WorkerFixtures {
  /** The shared server. */
  server: ServerInfo;
  /**
   * A REST client signed in as admin on the shared server. It logs in once per worker, not once
   * per test: every login attempt counts against the server's login throttle (per username and
   * per client address, in flight included), and the product limits must stay as they are, so the
   * suite keeps its share of attempts on the shared server small instead of bursting 20+ at once.
   */
  api: Api;
}

export const test = base.extend<Fixtures, WorkerFixtures>({
  baseURL: async ({ server }, use) => use(server.baseURL),
  server: [async ({}, use) => use(sharedServer()), { scope: 'worker' }],
  // The default session is the admin's; `test.use({ storageState: roleState('viewer') })` changes it.
  storageState: statePath('admin'),
  cspGuard: [
    async ({ context }, use) => {
      const seen: string[] = [];
      context.on('console', (msg) => {
        const text = msg.text();
        if (CSP_MARKERS.some((m) => m.test(text))) seen.push(text);
      });
      await use();
      expect(seen, 'console CSP violations').toEqual([]);
    },
    { auto: true },
  ],
  api: [
    async ({ server }, use) => {
      const api = await Api.login(server.baseURL, 'admin');
      await use(api);
      await api.dispose();
    },
    { scope: 'worker' },
  ],
  freshServer: async ({}, use) => {
    const started: DnsyServer[] = [];
    await use(async (opts) => {
      const s = await DnsyServer.start(opts);
      started.push(s);
      return s;
    });
    for (const s of started) await s.stop();
  },
});

export function roleState(role: 'admin' | 'operator' | 'viewer'): string {
  return statePath(role);
}

/** Sign in through the login form. */
export async function signIn(page: Page, username: string, password = PASSWORD): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

/** The main-area heading of the current page. */
export function heading(page: Page, name: string) {
  return page.getByRole('heading', { level: 1, name });
}

/** Sign the page's browser context in against another server (no form), e.g. a fresh one. */
export async function sessionFor(page: Page, baseURL: string, username = 'admin'): Promise<Api> {
  const res = await page.context().request.post(`${baseURL}/api/v1/auth/login`, {
    data: { username, password: PASSWORD },
  });
  if (!res.ok()) throw new Error(`login ${username}: ${res.status()}`);
  return Api.login(baseURL, username);
}
