import { createSocket } from 'node:dgram';

/** A DNS question with the fields the UI tests care about. */
export interface DnsAnswer {
  rcode: number;
  ips: string[];
}

function encodeName(name: string): Buffer {
  const parts = name.replace(/\.$/, '').split('.').filter(Boolean);
  const out: number[] = [];
  for (const p of parts) {
    out.push(p.length, ...Buffer.from(p, 'ascii'));
  }
  out.push(0);
  return Buffer.from(out);
}

/** Build a recursion-desired query for `name` and `qtype` (1 = A, 28 = AAAA). */
export function buildQuery(id: number, name: string, qtype = 1): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(qtype, 0);
  tail.writeUInt16BE(1, 2);
  return Buffer.concat([header, encodeName(name), tail]);
}

/** Offset just past a (possibly compressed) name starting at `at`. */
function skipName(msg: Buffer, at: number): number {
  let i = at;
  for (;;) {
    const len = msg[i] ?? 0;
    if (len === 0) return i + 1;
    if ((len & 0xc0) === 0xc0) return i + 2;
    i += len + 1;
  }
}

/** Decode the question name of a query and its type. */
export function parseQuestion(msg: Buffer): { name: string; qtype: number } {
  const labels: string[] = [];
  let i = 12;
  while ((msg[i] ?? 0) !== 0) {
    const len = msg[i] ?? 0;
    labels.push(msg.subarray(i + 1, i + 1 + len).toString('ascii'));
    i += len + 1;
  }
  return { name: labels.join('.').toLowerCase(), qtype: msg.readUInt16BE(i + 1) };
}

export function parseResponse(msg: Buffer): DnsAnswer {
  const rcode = msg.readUInt16BE(2) & 0x0f;
  const qd = msg.readUInt16BE(4);
  const an = msg.readUInt16BE(6);
  let i = 12;
  for (let q = 0; q < qd; q++) i = skipName(msg, i) + 4;
  const ips: string[] = [];
  for (let a = 0; a < an; a++) {
    i = skipName(msg, i);
    const type = msg.readUInt16BE(i);
    const rdlen = msg.readUInt16BE(i + 8);
    const rdata = msg.subarray(i + 10, i + 10 + rdlen);
    if (type === 1 && rdlen === 4) ips.push([...rdata].join('.'));
    i += 10 + rdlen;
  }
  return { rcode, ips };
}

let nextId = 1;

/** Send one UDP query to the server and wait for the answer (rejects after `timeoutMs`). */
export function query(port: number, name: string, qtype = 1, timeoutMs = 5000): Promise<DnsAnswer> {
  return new Promise((resolve, reject) => {
    const socket = createSocket('udp4');
    const id = nextId++ & 0xffff;
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error(`DNS query for ${name} timed out`));
    }, timeoutMs);
    socket.once('message', (msg) => {
      clearTimeout(timer);
      socket.close();
      resolve(parseResponse(msg));
    });
    socket.send(buildQuery(id, name, qtype), port, '127.0.0.1', (err) => {
      if (err) {
        clearTimeout(timer);
        socket.close();
        reject(err);
      }
    });
  });
}

/** Rcode of a response to a query, for the fake upstream. */
export function buildReply(
  query: Buffer,
  rcode: number,
  answers: { ip: string; ttl: number }[],
): Buffer {
  const { name } = parseQuestion(query);
  const qlen = encodeName(name).length + 4;
  const header = Buffer.alloc(12);
  query.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180 | rcode, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  const parts: Buffer[] = [header, query.subarray(12, 12 + qlen)];
  for (const a of answers) {
    const rr = Buffer.alloc(16);
    rr.writeUInt16BE(0xc00c, 0);
    rr.writeUInt16BE(1, 2);
    rr.writeUInt16BE(1, 4);
    rr.writeUInt32BE(a.ttl, 6);
    rr.writeUInt16BE(4, 10);
    a.ip.split('.').forEach((o, k) => rr.writeUInt8(Number(o), 12 + k));
    parts.push(rr);
  }
  return Buffer.concat(parts);
}
