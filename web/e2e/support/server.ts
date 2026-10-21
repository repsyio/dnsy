import { type ChildProcess, execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import { FakeUpstream } from './upstream';

export const WEB_DIR = resolve(__dirname, '../..');
export const REPO_DIR = resolve(WEB_DIR, '..');
export const RUN_DIR = join(WEB_DIR, '.e2e-run');

export const PASSWORD = 'e2e-password-1234';

/** The dnsy binary: `DNSY_BIN`, else `<cargo target dir>/debug/dnsy`. Needs the `embed-ui` feature. */
export function binaryPath(): string {
  const env = process.env['DNSY_BIN'];
  if (env) return env;
  const target = process.env['CARGO_TARGET_DIR'] ?? join(REPO_DIR, 'target');
  const bin = join(target, 'debug', 'dnsy');
  if (!existsSync(bin)) {
    throw new Error(
      `dnsy binary not found at ${bin}; run \`just e2e-ui\` (cargo build -p dnsy --features embed-ui)`,
    );
  }
  return bin;
}

export interface ServerOptions {
  /** Create the `admin`, `operator` and `viewer` users (default). `false` leaves a fresh database. */
  users?: boolean;
  /** Extra TOML appended to the generated config. */
  extraConfig?: string;
}

function toml(s: string): string {
  return JSON.stringify(s);
}

function waitFor<T>(what: string, fn: () => T | undefined, timeoutMs = 20000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolveFn, reject) => {
    const tick = (): void => {
      let value: T | undefined;
      try {
        value = fn();
      } catch {
        value = undefined;
      }
      if (value !== undefined) resolveFn(value);
      else if (Date.now() > deadline) reject(new Error(`timed out waiting for ${what}`));
      else setTimeout(tick, 50);
    };
    tick();
  });
}

/** A running `dnsy serve` with its own data directory and fake upstream. */
export class DnsyServer {
  private constructor(
    readonly dir: string,
    readonly configPath: string,
    readonly upstream: FakeUpstream,
    readonly baseURL: string,
    readonly dnsPort: number,
    private readonly child: ChildProcess,
    readonly logPath: string,
  ) {}

  static async start(opts: ServerOptions = {}): Promise<DnsyServer> {
    mkdirSync(RUN_DIR, { recursive: true });
    const dir = mkdtempSync(join(RUN_DIR, 'srv-'));
    mkdirSync(join(dir, 'zones'));
    const upstream = await FakeUpstream.start();
    const configPath = join(dir, 'dnsy.toml');
    writeFileSync(
      configPath,
      `[server]
data_dir = ${toml(join(dir, 'data'))}
[dns]
udp = ["127.0.0.1:0"]
tcp = ["127.0.0.1:0"]
[api]
listen = ["127.0.0.1:0"]
[zones]
dir = ${toml(join(dir, 'zones'))}
[dnssec]
validation = "off"
[resolver]
timeout_ms = 1000
attempts = 1
upstreams = [${toml(upstream.address)}]
[cache.prefetch]
enabled = false
[cache.serve_stale]
enabled = false
[filter]
block_mode = "null_ip"
[limits]
per_client_qps = 0
[logging]
level = "info"
${opts.extraConfig ?? ''}`,
    );
    const server = { dir, configPath, upstream };
    try {
      if (opts.users !== false) {
        for (const [name, role] of [
          ['admin', 'admin'],
          ['operator', 'operator'],
          ['viewer', 'viewer'],
        ] as const) {
          cli(configPath, ['user', 'create', name, '--role', role], { DNSY_PASSWORD: PASSWORD });
        }
      }
      const logPath = join(dir, 'dnsy.log');
      const ready = join(dir, 'ready.json');
      const log = openSync(logPath, 'w');
      const child = spawn(binaryPath(), ['--config', configPath, 'serve', '--ready-file', ready], {
        stdio: ['ignore', 'ignore', log],
        env: cleanEnv(),
      });
      let exited = false;
      child.once('exit', () => (exited = true));
      const addrs = await waitFor<{ api: string[]; udp: string[] }>('the server ready file', () => {
        if (exited) throw new Error(`dnsy exited early:\n${readFileSync(logPath, 'utf8')}`);
        return JSON.parse(readFileSync(ready, 'utf8')) as { api: string[]; udp: string[] };
      });
      const dnsPort = Number(addrs.udp[0]?.split(':').pop());
      return new DnsyServer(
        dir,
        configPath,
        upstream,
        `http://${addrs.api[0]}`,
        dnsPort,
        child,
        logPath,
      );
    } catch (e) {
      await upstream.stop();
      rmSync(dir, { recursive: true, force: true });
      throw e;
    }
  }

  /** Everything the server wrote to stderr. */
  logs(): string {
    return readFileSync(this.logPath, 'utf8');
  }

  /** The one-time setup code printed when the database has no users. */
  async bootstrapCode(): Promise<string> {
    return waitFor('the bootstrap code', () => /bootstrap code[^:]*: (\S+)/.exec(this.logs())?.[1]);
  }

  /** Create a user through the CLI (works while the server runs). */
  createUser(name: string, role: 'admin' | 'operator' | 'viewer', password = PASSWORD): void {
    cli(this.configPath, ['user', 'create', name, '--role', role], { DNSY_PASSWORD: password });
  }

  async stop(): Promise<void> {
    const done = new Promise<void>((r) => this.child.once('exit', () => r()));
    this.child.kill('SIGTERM');
    const timer = setTimeout(() => this.child.kill('SIGKILL'), 5000);
    await done;
    clearTimeout(timer);
    await this.upstream.stop();
    rmSync(this.dir, { recursive: true, force: true });
  }

  /** Persist enough to reattach from another process (global setup to workers). */
  describe(): ServerInfo {
    return {
      baseURL: this.baseURL,
      dnsPort: this.dnsPort,
      upstreamPort: this.upstream.port,
      configPath: this.configPath,
    };
  }
}

export interface ServerInfo {
  baseURL: string;
  dnsPort: number;
  upstreamPort: number;
  configPath: string;
}

function cleanEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env = { ...process.env, ...extra };
  for (const k of ['DNSY_PASSWORD', 'DNSY_DNSSEC_PASSPHRASE', 'DNSY_TOKEN']) {
    if (!(k in extra)) delete env[k];
  }
  return env;
}

export function cli(configPath: string, args: string[], env: Record<string, string> = {}): string {
  return execFileSync(binaryPath(), ['--config', configPath, ...args], {
    env: cleanEnv(env),
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

/** A short random suffix for names that must not collide between parallel tests. */
export function uid(): string {
  return randomBytes(4).toString('hex');
}
