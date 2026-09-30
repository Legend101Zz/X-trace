import { copyFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const target = path.join(root, 'public/assets/fonts');
await mkdir(target, { recursive: true });
for (const name of [
  'chivo-latin-400-normal.woff2',
  'chivo-latin-600-normal.woff2',
  'azeret-mono-latin-400-normal.woff2',
]) {
  const family = name.startsWith('azeret') ? 'azeret-mono' : 'chivo';
  await copyFile(path.join(root, 'node_modules/@fontsource', family, 'files', name), path.join(target, name));
}
