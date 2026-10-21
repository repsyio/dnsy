// Precompresses the Angular build output: writes `<file>.br` and `<file>.gz` next to every
// text asset so the embedded UI can serve them with `Content-Encoding` and no per-request work.
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { extname, join } from 'node:path';
import { brotliCompressSync, constants, gzipSync } from 'node:zlib';

const root = new URL('../dist/dnsy/browser', import.meta.url).pathname;
const compressible = new Set(['.html', '.js', '.mjs', '.css', '.svg', '.json', '.txt', '.webmanifest', '.ico']);
const minBytes = 256;

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* walk(path);
    else yield path;
  }
}

let before = 0;
let brotli = 0;
let gzip = 0;
for (const file of walk(root)) {
  if (!compressible.has(extname(file)) || statSync(file).size < minBytes) continue;
  const data = readFileSync(file);
  const br = brotliCompressSync(data, {
    params: {
      [constants.BROTLI_PARAM_QUALITY]: constants.BROTLI_MAX_QUALITY,
      [constants.BROTLI_PARAM_SIZE_HINT]: data.length,
    },
  });
  const gz = gzipSync(data, { level: 9 });
  writeFileSync(`${file}.br`, br);
  writeFileSync(`${file}.gz`, gz);
  before += data.length;
  brotli += br.length;
  gzip += gz.length;
}
console.log(`compress-dist: ${before} bytes -> ${brotli} brotli, ${gzip} gzip`);
