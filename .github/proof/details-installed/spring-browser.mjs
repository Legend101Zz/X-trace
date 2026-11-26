import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { chromium, expect } from '@playwright/test';

const input = JSON.parse(await readFile(process.argv[2], 'utf8'));
const { url, mode, recordingId, events, result, nonce } = input;
const { origin, hash } = new URL(url);
const token = new URLSearchParams(hash.slice(1)).get('token');
assert.match(origin, /^http:\/\/127\.0\.0\.1:[0-9]+$/);
assert.match(token, /^[a-zA-Z0-9_-]{43}$/);
assert.match(recordingId, /^[a-f0-9-]{36}$/);
assert.ok(mode === 'fine' || mode === 'coarse');
const broad = '/api/v1/recordings';
const detailPath = broad + '/' + recordingId;
const isDetail = (response) => {
  const parsed = new URL(response.url());
  return parsed.origin === origin && parsed.pathname === detailPath && response.request().method() === 'GET';
};
const reads = new Set(['/', '/app.js', '/index.css', '/favicon.ico',
  '/assets/fonts/chivo-latin-400-normal.woff2', '/assets/fonts/chivo-latin-600-normal.woff2',
  '/assets/fonts/azeret-mono-latin-400-normal.woff2', '/api/v1/endpoints', broad, detailPath]);
const browser = await chromium.launch({ headless: true });
let observation;
try {
  const context = await browser.newContext({ viewport:{width:1440,height:900}, hasTouch:mode === 'coarse', serviceWorkers:'block' });
  let exchanges = 0;
  let refused = 0;
  await context.route('**/*', (route) => {
    const req = route.request();
    const target = new URL(req.url());
    const local = target.origin === origin && !req.url().includes(token) && !req.headers().referer?.includes(token);
    if (local && req.method() === 'GET' && reads.has(target.pathname)) return route.continue();
    if (local && req.method() === 'POST' && target.pathname === '/api/v1/auth/exchange'
      && !target.search && exchanges === 0 && req.postData() === JSON.stringify({token})) {
      exchanges++;
      return route.continue();
    }
    refused++;
    return route.abort();
  });
  await context.routeWebSocket('**/*', (socket) => { refused++; return socket.close(); });
  const page = await context.newPage();
  let errors = 0;
  page.on('pageerror', () => { errors++; });
  page.on('console', (message) => { if (message.type() === 'error') errors++; });
  page.setDefaultTimeout(8000);
  page.setDefaultNavigationTimeout(10000);
  const select = (control) => mode === 'coarse' ? control.tap() : control.click();
  await page.goto(url);
  await expect(page.getByText('Local viewer connected', { exact:true })).toBeVisible();
  assert.ok(await page.evaluate((pointer) => matchMedia('(pointer: ' + pointer + ')').matches, mode));
  const unmatched = page.getByRole('button',{name:'Not linked to an endpoint',exact:true});
  if (!await unmatched.isVisible()) {
    const requests = page.locator('#header-requests');
    if (await requests.isVisible() && await requests.getAttribute('aria-expanded') === 'false') await select(requests);
  }
  await select(unmatched);
  const capture = page.locator('.recording-list .recording').filter({hasText:recordingId});
  const [recording] = await Promise.all([page.waitForResponse(isDetail), select(capture)]);
  assert.equal(recording.status(), 200);
  const evidence = await recording.json();
  const current = page.locator('.event[aria-current="true"] .event-seq');
  await expect(current).toHaveText(events[0][0]);
  assert.equal(evidence.recordingId, recordingId);
  assert.equal(evidence.outcome?.kind,'responded');
  assert.equal(evidence.outcome?.httpStatus,210);
  assert.ok(evidence.events.length > 0);
  assert.deepEqual(evidence.events.map(({ sequence, eventId }) => [sequence, eventId]), events.slice(0, evidence.events.length));
  for (const cell of evidence.events) assert.match(cell.sequence, /^[0-9]+$/);
  if (mode === 'fine') {
    const event = evidence.events.find(({kind, source, symbol}) => kind === 'recording_event_kind:frame_enter'
      && symbol === 'ServletBoundaryController.uncommitted'
      && source?.status === 'matched' && typeof source.excerpt === 'string' && source.excerpt.length > 0);
    assert.ok(event?.eventId);
    const row = page.locator('#events-panel .event').filter({has:page.locator('.event-seq').filter({hasText:new RegExp('^' + event.sequence + '$')})});
    await row.click();
    await expect(current).toHaveText(event.sequence);
    const tab = page.getByRole('tablist',{name:'Inspector evidence'}).getByRole('tab',{name:'Details',exact:true});
    await tab.click();
    await expect(tab).toHaveAttribute('aria-selected','true');
    const details = page.getByRole('region',{name:'Event details',exact:true});
    await expect(details.getByText(event.kind,{exact:true})).toBeVisible();
    const identity = details.locator('[data-event-field="event-id"]');
    await expect(identity).toHaveText(event.eventId);
    assert.ok(await identity.evaluate((field) => {
      const port = field.closest('.evidence-content');
      if (!port || port.scrollTop !== 0) return false;
      const box = port.getBoundingClientRect();
      const left = box.left + port.clientLeft;
      const top = box.top + port.clientTop;
      const range = document.createRange();
      range.selectNodeContents(field);
      const lines = Array.from(range.getClientRects());
      return lines.length > 0 && lines.every((rect) => {
        if (rect.width <= 0 || rect.height <= 0 || rect.left < Math.max(0,left)
          || rect.right > Math.min(innerWidth,left+port.clientWidth) || rect.top < Math.max(0,top)
          || rect.bottom > Math.min(innerHeight,top+port.clientHeight)) return false;
        const dx = Math.min(0.5,rect.width/2), dy = Math.min(0.5,rect.height/2);
        return [[rect.left+dx,rect.top+dy],[rect.right-dx,rect.top+dy],[rect.left+dx,rect.bottom-dy],
          [rect.right-dx,rect.bottom-dy],[rect.left+rect.width/2,rect.top+rect.height/2]]
          .every(([x,y]) => field.contains(document.elementFromPoint(x,y)));
      });
    }));
    observation = {identityReadable:true};
  } else {
    const controls = page.locator('#evidence-panel .wide-focus-event, #evidence-panel [role="tab"]');
    await expect(controls).toHaveCount(4);
    assert.ok(await controls.evaluateAll((buttons) => buttons.every((button) => {
      const rect = button.getBoundingClientRect();
      const x = rect.left + rect.width / 2, y = rect.top + rect.height / 2;
      return rect.width >= 44 && rect.height >= 44
        && [[x,rect.top+1],[x,rect.bottom-1],[rect.left+1,y],[rect.right-1,y],[x,y]]
          .every(([px,py]) => button.contains(document.elementFromPoint(px,py)));
    })));
    observation = {touchTargets:4};
  }
  await context.close();
  assert.equal(exchanges,1);
  assert.equal(refused,0);
  assert.equal(errors,0);
} finally {
  await browser.close();
}
await writeFile(result, JSON.stringify({mode,nonce,...observation}), { flag:'wx',mode:0o600 });
