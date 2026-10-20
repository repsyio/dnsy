// Copy the shared brand assets (../branding) into public/ so the Angular build can ship them.
// public/ is generated and git-ignored; branding/ stays the single source.
import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const branding = join(root, '..', 'branding');
const out = join(root, 'public');

rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, 'mascot'), { recursive: true });
for (const f of ['mark.svg', 'favicon.svg']) cpSync(join(branding, f), join(out, f));
cpSync(join(branding, 'mascot'), join(out, 'mascot'), { recursive: true });
