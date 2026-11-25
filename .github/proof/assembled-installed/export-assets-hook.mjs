// Instrument only the private installed export browser. The tracked driver and its
// authenticated API collector remain unchanged and retain their own digest receipt.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { appendFile, lstat, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';

const root = process.env.SHARED_ROOT;
assert.ok(root && resolve(root) === root);
const shared = JSON.parse(await readFile(join(root, 'private/package.json'), 'utf8'));
const receipt = join(process.env.PROOF_ROOT, 'private/export-served.jsonl');
const info = await lstat(receipt);
assert.ok(info.isFile() && !info.isSymbolicLink() && info.uid === process.getuid()
  && (info.mode & 0o777) === 0o600 && info.nlink === 1 && info.size === 0);
const { chromium } = createRequire(join(process.cwd(), 'web/app/package.json'))('@playwright/test');
const launch = chromium.launch.bind(chromium);
chromium.launch = async (...launchArgs) => {
  const browser = await launch(...launchArgs);
  const newContext = browser.newContext.bind(browser);
  browser.newContext = async (options) => {
    const context = await newContext(options);
    const newPage = context.newPage.bind(context);
    context.newPage = async (...args) => {
      const page = await newPage(...args);
      const goto = page.goto.bind(page);
      let bound = false;
      page.goto = async (url, ...rest) => {
        assert.equal(bound, false, 'one immutable viewer binding per export viewport');
        const bootstrap = new URL(url);
        assert.match(bootstrap.origin, /^http:\/\/127\.0\.0\.1:[0-9]+$/);
        assert.match(bootstrap.hash, /^#token=[a-zA-Z0-9_-]{43}$/);
        const response = await goto(url, ...rest);
        let checked = 0;
        for (const [name, expected] of Object.entries(shared.assetDigests)) {
          assert.match(expected, /^[0-9a-f]{64}$/);
          const path = name === 'index.html' ? '/' : `/${name}`;
          const asset = await context.request.get(bootstrap.origin + path, { timeout: 10_000, maxRedirects: 0 });
          assert.equal(asset.status(), 200);
          const body = await asset.body();
          assert.ok(body.length <= 20 * 1024 * 1024);
          assert.equal(createHash('sha256').update(body).digest('hex'), expected);
          await asset.dispose();
          checked++;
        }
        assert.equal(checked, 6);
        const row = { sourceSha: shared.sourceSha, sourceTree: shared.sourceTree,
          archiveSha256: shared.archiveSha256, uiManifestSha256: shared.uiManifestSha256,
          installedCliSha256: shared.installedCliSha256, installedAgentSha256: shared.installedAgentSha256,
          width: options.viewport.width, height: options.viewport.height,
          pointer: options.hasTouch ? 'coarse' : 'fine', servedAssets: checked };
        await appendFile(receipt, JSON.stringify(row) + '\n');
        bound = true;
        return response;
      };
      return page;
    };
    return context;
  };
  return browser;
};
