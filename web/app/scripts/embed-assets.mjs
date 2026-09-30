import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repo = path.resolve(root, '../..');
const dist = path.join(root, 'dist');
const target = path.join(repo, 'crates/xtrace-daemon/assets/ui');
const checkOnly = process.argv.includes('--check');
const files = [
  'index.html', 'app.js', 'index.css',
  'assets/fonts/chivo-latin-400-normal.woff2',
  'assets/fonts/chivo-latin-600-normal.woff2',
  'assets/fonts/azeret-mono-latin-400-normal.woff2',
];

for (const file of files) {
  const source = path.join(dist, file);
  const destination = path.join(target, file.replace(/^assets\//, ''));
  const sourceBytes = await readFile(source);
  if (checkOnly) {
    const destinationBytes = await readFile(destination).catch(() => null);
    if (!destinationBytes || !sourceBytes.equals(destinationBytes)) {
      throw new Error(`Embedded viewer asset drift: ${file}`);
    }
  } else {
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, sourceBytes);
  }
}

const names = (await readdir(dist, { recursive: true })).sort();
const filesOnDisk = [];
for (const name of names) {
  if ((await stat(path.join(dist, name))).isFile()) filesOnDisk.push(name);
}
const unexpected = filesOnDisk.filter((name) => !files.includes(name));
if (unexpected.length) throw new Error(`Unexpected viewer build outputs: ${unexpected.join(', ')}`);

const manifest = files.map(async (file) => {
  const bytes = await readFile(path.join(dist, file));
  return `${createHash('sha256').update(bytes).digest('hex')}  ${file}`;
});
const rendered = `${(await Promise.all(manifest)).join('\n')}\n`;
const manifestPath = path.join(target, 'assets.sha256');
if (checkOnly) {
  const saved = await readFile(manifestPath, 'utf8');
  if (saved !== rendered) throw new Error('Embedded viewer asset manifest drift');
} else {
  await writeFile(manifestPath, rendered);
}
