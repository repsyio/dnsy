import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { request } from '@playwright/test';
import { DnsyServer, PASSWORD, RUN_DIR } from './support/server';

export const ROLES = ['admin', 'operator', 'viewer'] as const;

export function statePath(role: string): string {
  return join(RUN_DIR, `state-${role}.json`);
}

/** Starts one shared dnsy (embedded UI, fake upstream) and signs the three role users in. */
export default async function globalSetup(): Promise<() => Promise<void>> {
  const server = await DnsyServer.start();
  mkdirSync(RUN_DIR, { recursive: true });
  for (const role of ROLES) {
    const ctx = await request.newContext({ baseURL: server.baseURL });
    const res = await ctx.post('/api/v1/auth/login', {
      data: { username: role, password: PASSWORD },
    });
    if (!res.ok()) throw new Error(`login ${role}: ${res.status()} ${await res.text()}`);
    await ctx.storageState({ path: statePath(role) });
    await ctx.dispose();
  }
  const info = JSON.stringify(server.describe());
  writeFileSync(join(RUN_DIR, 'shared.json'), info);
  process.env['DNSY_E2E_SERVER'] = info;
  return async () => {
    await server.stop();
  };
}
