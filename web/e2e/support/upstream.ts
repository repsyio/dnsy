import { createSocket, type Socket } from 'node:dgram';
import { buildReply, parseQuestion } from './dns';

/** The address every A query to the fake upstream resolves to. */
export const UPSTREAM_IP = '192.0.2.7';

/**
 * A UDP DNS server on a free loopback port. Every A query gets `UPSTREAM_IP` (TTL 300) except
 * names starting with `nx.`, which get NXDOMAIN. It counts the queries it saw.
 */
export class FakeUpstream {
  received = 0;
  private constructor(
    private readonly socket: Socket,
    readonly port: number,
  ) {}

  static async start(): Promise<FakeUpstream> {
    const socket = createSocket('udp4');
    await new Promise<void>((resolve) => socket.bind(0, '127.0.0.1', resolve));
    const upstream = new FakeUpstream(socket, socket.address().port);
    socket.on('message', (msg, rinfo) => {
      upstream.received++;
      const { name, qtype } = parseQuestion(msg);
      const reply = name.startsWith('nx.')
        ? buildReply(msg, 3, [])
        : buildReply(msg, 0, qtype === 1 ? [{ ip: UPSTREAM_IP, ttl: 300 }] : []);
      socket.send(reply, rinfo.port, rinfo.address);
    });
    return upstream;
  }

  get address(): string {
    return `127.0.0.1:${this.port}`;
  }

  stop(): Promise<void> {
    return new Promise((resolve) => this.socket.close(() => resolve()));
  }
}
