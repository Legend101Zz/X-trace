/** Genuine viewer planning only. Never calls an application endpoint or an exercise executor. */
import assert from 'node:assert/strict';
import { writeFile, rename, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
const require = createRequire(join(process.cwd(), 'web/app/package.json'));
const { chromium, expect } = require('@playwright/test');
const configBytes = await new Promise((resolve, reject) => {
  const chunks = []; let size = 0;
  process.stdin.on('data', chunk => { size += chunk.length; if (size > 65536) reject(new Error('input bound')); else chunks.push(chunk); });
  process.stdin.on('end', () => resolve(Buffer.concat(chunks))); process.stdin.on('error', reject);
});
const c = JSON.parse(configBytes);
const widths = [[320,640],[736,900],[1024,768],[1280,900],[1440,900]];
const checks = ['selection','opener','focus-trap','missing-inputs','canonical-revision','review','fresh-consent','approval',
  'atomic-edit','superseded-read','replacement-consent','readback','reload','close-focus','private-persistence','no-external-requests'];
const actions = ['create','edit','show','review','approve'];
const report = {schemaVersion:1,kind:'owner-plan-browser',sourceSha:c.sourceSha,sourceTree:c.sourceTree,
  wrapperSha:c.wrapperSha,runId:c.runId,attempt:c.attempt,receiptId:c.receiptId,
  status:'failed',stage:'bootstrap',cells:[],routes:Object.fromEntries(actions.map(x=>[x,0])),
  observedRoutes:Object.fromEntries(actions.map(x=>[x,0])),routeCountMeaning:'verified-authenticated-response',
  externalRequests:0,consoleErrors:0,downloads:0,privateLeaks:0,focusDiagnostic:null,failureLocation:null,expiry:'unreached',serverExpiredDrafts:0,pendingWriteClose:'unreached'};
const privateDocs = [];
const save = async () => { const p=join(c.output,'browser.json'); await writeFile(p+'.tmp',JSON.stringify(report)+'\n',{mode:0o600}); await rename(p+'.tmp',p); };
await mkdir(c.output,{recursive:true,mode:0o700});
const browser=await chromium.launch({headless:true});
let stage='bootstrap';
try {
  assert.match(c.origin,/^http:\/\/127\.0\.0\.1:[0-9]+$/);
  assert.match(c.target,/^http:\/\/127\.0\.0\.1:[0-9]+$/);
  const [cookieName,...cookieValue]=c.cookie.split('=');
  assert.ok(cookieName && cookieValue.length);
  for (const [width,height] of widths) for (const pointer of ['fine','coarse']) {
    const cell={width,height,pointer,status:'attempted',checks:Object.fromEntries(checks.map(x=>[x,'unreached']))};
    report.cells.push(cell); await save();
    const context=await browser.newContext({viewport:{width,height},hasTouch:pointer==='coarse',serviceWorkers:'block'});
    await context.addCookies([{name:cookieName,value:cookieValue.join('='),url:c.origin,httpOnly:true,sameSite:'Strict'}]);
    const page=await context.newPage(); page.setDefaultTimeout(8000); page.setDefaultNavigationTimeout(10000);
    const secrets=[`ordinary-proof-${randomBytes(16).toString('hex')}`,`ordinary-value-${randomBytes(16).toString('hex')}`];
    let errorCount=0, external=0,downloads=0,unexpectedWrites=0;
    const leaks=text=>secrets.some(x=>String(text).includes(x));
    page.on('console',m=>{ if(m.type()==='error')errorCount++; if(leaks(m.text()))report.privateLeaks++; });
    page.on('pageerror',e=>{errorCount++; if(leaks(e.message))report.privateLeaks++;});
    page.on('download',()=>downloads++);
    page.on('request',request=>{
      const url=new URL(request.url());if(url.origin!==c.origin)return;
      const path=url.pathname,method=request.method();
      const action=method==='POST'&&path==='/api/v1/exercise/plans'?'create':
        method==='GET'&&/^\/api\/v1\/exercise\/plans\/[0-9a-f]{64}$/.test(path)?'show':
        method==='POST'?/^\/api\/v1\/exercise\/plans\/[0-9a-f]{64}\/(edit|review|approve)$/.exec(path)?.[1]:undefined;
      if(action)report.observedRoutes[action]++;
    });

    // A boundary guard aborts unexpected traffic and records it as failure, never successful zero-send evidence.
    await context.route('**/*',async route=>{
      const req=route.request(), url=new URL(req.url());
      if(url.origin!==c.origin){external++;return route.abort();}
      const planWrite=req.method()==='POST' && !url.search &&
        (url.pathname==='/api/v1/exercise/plans' || /^\/api\/v1\/exercise\/plans\/[0-9a-f]{64}\/(edit|review|approve)$/.test(url.pathname));
      if(!['GET','HEAD'].includes(req.method()) && !planWrite){unexpectedWrites++;return route.abort();}
      return route.continue();
    });
    const click=loc=>pointer==='coarse'?loc.tap():loc.click();
    const mark=async(name,fn)=>{stage=name;report.stage=name;await save();await fn();cell.checks[name]='passed';await save();};
    const dialog=()=>page.getByRole('dialog',{name:'Send again',exact:true});
    const fit=async(scope)=>{
      assert.ok(await scope.evaluate(e=>e.scrollWidth<=e.clientWidth));
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    };
    const hit=async(control)=>{
      await control.scrollIntoViewIfNeeded();
      const value=await control.evaluate(e=>{const b=e.getBoundingClientRect();const p=document.elementFromPoint(b.x+b.width/2,b.y+b.height/2);
        return {width:b.width,height:b.height,hit:!!p&&e.contains(p)};});
      assert.ok(value.hit);
      if(pointer==='coarse'||width<1024)assert.ok(value.width>=44&&value.height>=44);
    };
    const select=async()=>{
      await page.goto(c.origin,{waitUntil:'domcontentloaded'});
      const endpoint=page.locator('.endpoint-card');await expect(endpoint).toHaveCount(1);
      await click(endpoint);const recording=page.getByRole('button',{name:new RegExp(c.recordingId)});await click(recording);
      const pane=page.getByRole('tablist',{name:'Viewer panes'}).getByRole('tab',{name:'Steps',exact:true});
      if(await pane.isVisible())await click(pane);
      await expect(page.locator('.event-seq').first()).toBeVisible();
      const observed=await page.locator('.event-seq').allTextContents();assert.deepEqual(observed,c.sequences);
    };
    let opener;
    const focusState=async()=>{
      const observed=await page.evaluate(()=>{
        const active=document.activeElement,modal=document.querySelector('dialog.viewer-dialog');
        const tag=active?.localName;
        const role=!active?'none':active===document.body?'document-body':active===modal?'dialog':
          active===modal?.querySelector('.viewer-dialog-header button')?'dialog-close':tag==='summary'?'disclosure-summary':
          tag==='input'?(active.type==='checkbox'?'checkbox':'text-input'):tag==='select'?'select':
          tag==='textarea'?'textarea':tag==='button'?'button':tag==='a'?'link':/^h[1-6]$/.test(tag??'')?'programmatic-heading':'other';
        const tab=active instanceof HTMLElement?(active.tabIndex<0?'negative':active.tabIndex>0?'positive':'zero'):'none';
        const more=document.querySelector('.phone-replay-toolbar .phone-actions > button[aria-controls]');
        return {activeRole:role,activeTabIndex:tab,insideModal:!!modal?.contains(active),nativeModal:!!modal?.matches(':modal'),
          moreExpanded:more?more.getAttribute('aria-expanded')==='true':null,moreVisible:more?more.getClientRects().length>0:null,
          activeDisabled:active instanceof Element?active.matches(':disabled'):false,
          planBusy:modal?.querySelector('.plan-sheet')?modal.querySelector('.plan-sheet').getAttribute('aria-busy')==='true':null};
      });
      return {...observed,openerVisible:opener?await opener.isVisible():null,
        openerFocused:opener&&await opener.count()===1?await opener.evaluate(e=>e===document.activeElement):null};
    };
    const probe=async(name,fn)=>{
      if(!['focus-trap','pending-write-close'].includes(stage))return fn();
      const snapshot=async state=>{
        try{return {subcheck:name,state,...await focusState()};}
        catch{return {subcheck:name,state:'snapshot-unavailable',activeRole:'none',activeTabIndex:'none',insideModal:false,
          nativeModal:false,moreExpanded:null,moreVisible:null,activeDisabled:false,planBusy:null,openerVisible:null,openerFocused:null};}
      };
      report.focusDiagnostic=await snapshot('started');await save();
      try{const result=await fn();report.focusDiagnostic=await snapshot('passed');await save();return result;}
      catch(error){
        // No DOM text, attribute values, request values or exception message leave this process.
        report.focusDiagnostic=await snapshot('failed');
        const match=/(?:^|[\s(])[^\r\n]*?owner-plan-browser\.mjs:(\d{1,5}):(\d{1,5})/.exec(String(error?.stack??''));
        if(match)report.failureLocation={file:'owner-plan-browser.mjs',line:Number(match[1]),column:Number(match[2])};
        await save();throw error;
      }
    };
    const open=async()=>{
      if(width<700){const more=page.getByRole('group',{name:'Replay navigation'}).getByRole('button',{name:'More',exact:true});
        if(await more.getAttribute('aria-expanded')!=='true')await probe('phone-more-open',()=>click(more));}
      if(width<1024){opener=page.getByRole('button',{name:'Tools',exact:true});await probe('compact-tools-hit',()=>hit(opener));await probe('compact-tools-open',()=>click(opener));
        const plan=page.getByRole('button',{name:'Send again…',exact:true});await probe('plan-action-hit',()=>hit(plan));await probe('plan-action-open',()=>click(plan));}
      else{
        if(width<1280){const summary=page.locator('.recording-more summary');
          if(!await summary.evaluate(e=>e.parentElement.open))await probe('recording-more-open',()=>click(summary));}
        opener=page.locator(width<1280?'.plan-trigger--more':'.plan-trigger--bar');await probe('plan-action-hit',()=>hit(opener));await probe('plan-action-open',()=>click(opener));
      }
      await probe('modal-visible',()=>expect(dialog()).toBeVisible());
      await probe('initial-close-focus',()=>expect(dialog().getByRole('button',{name:'Close',exact:true})).toBeFocused());
      await probe('modal-fit',()=>fit(dialog()));
    };
    const close=async(escape=false)=>{
      if(escape)await probe('escape-key',()=>page.keyboard.press('Escape'));
      else await probe('close-button',()=>click(dialog().getByRole('button',{name:'Close',exact:true})));
      await probe('closed-modal-absent',()=>expect(dialog()).toHaveCount(0));
      await probe('return-opener-visible',()=>expect(opener).toBeVisible());
      await probe('return-opener-focused',()=>expect(opener).toBeFocused());
      await probe('return-opener-enabled',async()=>assert.equal(await opener.evaluate(e=>e.matches(':disabled')),false));
    };
    const get=label=>dialog().getByLabel(label,{exact:true});
    const field=term=>dialog().locator('dt').filter({hasText:new RegExp('^'+term+'$')}).locator('xpath=following-sibling::dd[1]');
    const showPhase=async phase=>{await expect(field('Saved phase')).toHaveText(phase);};
    const request=async(action,button,{expired=false}={})=>{
      const wanted=(url,method)=>{const path=new URL(url).pathname;return action==='create'?method==='POST'&&path==='/api/v1/exercise/plans':
        action==='show'?method==='GET'&&/^\/api\/v1\/exercise\/plans\/[0-9a-f]{64}$/.test(path):
        method==='POST'&&new RegExp('^/api/v1/exercise/plans/[0-9a-f]{64}/'+action+'$').test(path);};
      const wait=page.waitForResponse(r=>wanted(r.url(),r.request().method()));await click(button);const response=await wait;
      assert.equal(response.status(),200);assert.equal(response.headers()['cache-control'],'no-store');
      const req=response.request();const headers=await req.allHeaders();assert.equal(headers['x-xtrace-client'],'viewer-v1');
      if(action!=='show'){assert.equal(headers.origin,c.origin);assert.equal(headers['sec-fetch-site'],'same-origin');}
      const doc=await response.json();assert.equal(doc.kind,'exercise_plan_review');assert.equal(doc.project_id,c.projectId);
      assert.equal(doc.observed_recording.recording_id,c.recordingId);assert.equal(doc.observed_recording.operation_id,c.operationId);
      assert.equal(doc.observed_recording.version_evidence,'not_observed');
      assert.equal(doc.selected_catalog_operation.catalog.revision_id,c.revisionId);
      assert.equal(doc.selected_catalog_operation.catalog.operation_version_id,c.operationVersionId);
      assert.equal(doc.preview.plan_hash,doc.plan_hash);assert.match(doc.plan_hash,/^[0-9a-f]{64}$/);
      assert.equal(doc.preview.items.length,1);assert.equal(doc.preview.items[0].operation_id,c.operationId);
      assert.equal(doc.requests_sent,0);assert.equal(doc.execution_available,false);assert.equal(doc.expired,expired);
      assert.equal(doc.target.base_url,c.target);assert.equal(doc.target.operator_owned_development,true);
      assert.equal(doc.preview.items[0].effect,'mutating');
      if(action==='create'||action==='edit')assert.equal(req.postDataJSON().revision_id,c.revisionId);
      if(await dialog().count()){
        await expect(field('Plan ID')).toHaveText(doc.plan_id);await expect(field('Plan hash')).toHaveText(doc.plan_hash);
        await expect(field('Item ID')).toHaveText(doc.preview.items[0].item_id);await expect(field('Recording')).toHaveText(c.recordingId);
        await expect(field('Observed operation')).toHaveText(c.operationId);await expect(field('Selected catalog revision')).toHaveText(c.revisionId);
        await expect(field('Selected operation version')).toHaveText(c.operationVersionId);await expect(field('Target')).toHaveText(c.target);
        if(doc.body.source==='operator')await expect(field('Request body').locator('pre')).toHaveText(doc.body.content);
      }
      secrets.push(doc.plan_hash,doc.plan_id,doc.preview.items[0].item_id,'ordinary_owner_handle');
      report.routes[action]++;privateDocs.push({cell:report.cells.length-1,action,doc});await save();return doc;
    };
    const approve=async()=>{
      const box=dialog().getByRole('checkbox');await expect(box).toHaveCount(2);
      const save=dialog().getByRole('button',{name:'Save item approval',exact:true});await expect(save).toBeDisabled();
      await box.nth(0).check();await expect(save).toBeDisabled();await box.nth(1).check();
      const doc=await request('approve',save);assert.equal(doc.phase.phase,'approved');
      assert.deepEqual(doc.phase.item_ids,[doc.preview.items[0].item_id]);return doc;
    };
    try {
      await mark('selection',select);await mark('opener',open);
      await mark('focus-trap',async()=>{
        await probe('reverse-tab-key',()=>page.keyboard.press('Shift+Tab'));
        await probe('reverse-tab-contained',async()=>assert.ok(await dialog().evaluate(e=>e.contains(document.activeElement))));
        await probe('reverse-tab-summary',()=>expect(dialog().locator('details:not([open]) > summary').last()).toBeFocused());
        await probe('forward-tab-key',()=>page.keyboard.press('Tab'));
        await probe('forward-tab-close',()=>expect(dialog().getByRole('button',{name:'Close',exact:true})).toBeFocused());
        // Actual pointerdown inside native dialog must not collapse phone More and hide its return target.
        await probe('catalog-pointerdown',()=>click(get('Catalog revision ID')));await close();await open();
      });
      await get('Catalog revision ID').fill(c.revisionId.toUpperCase());
      await get('Operation version ID').fill(c.operationVersionId);await get('Loopback HTTP origin with port').fill(c.target);
      await get('I own this local development application.').check();
      await get('Plan lifetime in seconds').fill('900');
      await click(dialog().getByRole('button',{name:'Add input',exact:true}));
      await get('Name').fill('owner-note');await get('Required').check();
      let missing;
      await mark('missing-inputs',async()=>{
        missing=await request('create',dialog().getByRole('button',{name:'Create private plan',exact:true}));
        assert.equal(missing.body.source,'not_recorded');assert.equal(missing.inputs[0].value.source,'unresolved');
        const doc=await request('review',dialog().getByRole('button',{name:'Mark this plan reviewed',exact:true}));
        assert.equal(doc.ready_for_approval,false);await expect(dialog().getByRole('button',{name:'Save item approval',exact:true})).toHaveCount(0);
      });
      cell.checks['canonical-revision']='passed';
      await click(dialog().getByRole('button',{name:'Edit plan',exact:true}));
      await get('Catalog revision ID').fill(c.revisionId.toUpperCase());await get('Body source').selectOption('operator');
      await get('Private body').fill(JSON.stringify({description:secrets[0]}));
      await get('Source').selectOption('operator');await get('Private value').fill(secrets[1]);
      // A credential is represented solely by a private opaque handle, never a credential value.
      await click(dialog().getByRole('button',{name:'Add input',exact:true}));
      const input2=dialog().getByRole('group',{name:'Input 2',exact:true});await input2.getByLabel('Name',{exact:true}).fill('Authorization');
      await input2.getByLabel('Location',{exact:true}).selectOption('header');await input2.getByLabel('Source',{exact:true}).selectOption('credential_reference');
      await input2.getByLabel('Reference name',{exact:true}).fill('ordinary_owner_handle');
      const ready=await request('edit',dialog().getByRole('button',{name:'Save replacement plan',exact:true}));
      assert.equal(ready.supersedes,missing.plan_hash);assert.equal(ready.phase.phase,'draft');
      await mark('review',async()=>{const doc=await request('review',dialog().getByRole('button',{name:'Mark this plan reviewed',exact:true}));
        assert.equal(doc.ready_for_approval,true);assert.equal(doc.inputs[1].value.reference,'ordinary_owner_handle');});
      await mark('fresh-consent',async()=>{await expect(dialog().getByRole('checkbox').nth(0)).not.toBeChecked();
        await expect(dialog().getByRole('checkbox').nth(1)).not.toBeChecked();});
      let approved;await mark('approval',async()=>{approved=await approve();await showPhase('approved');});
      await page.screenshot({path:join(c.output,`plan-approved-${pointer}-${width}.png`)});
      let replacement;
      await mark('atomic-edit',async()=>{
        await click(dialog().getByRole('button',{name:'Edit plan',exact:true}));await get('Private body').fill(JSON.stringify({description:secrets[0]+'-edited'}));
        replacement=await request('edit',dialog().getByRole('button',{name:'Save replacement plan',exact:true}));
        assert.equal(replacement.supersedes,approved.plan_hash);assert.notEqual(replacement.plan_id,approved.plan_id);
        assert.notEqual(replacement.plan_hash,approved.plan_hash);assert.notEqual(replacement.preview.items[0].item_id,approved.preview.items[0].item_id);
        assert.equal(replacement.phase.phase,'draft');
      });
      const restore=async(hash)=>{
        await close();await open();await get('Saved plan hash').fill(hash);
        return request('show',dialog().getByRole('button',{name:'Show saved plan',exact:true}));
      };
      await mark('superseded-read',async()=>{const doc=await restore(approved.plan_hash);
        assert.equal(doc.phase.phase,'superseded');assert.equal(doc.phase.replacement_hash,replacement.plan_hash);
        assert.deepEqual(doc.phase.previous,approved.phase);await expect(dialog().getByRole('button',{name:'Save item approval',exact:true})).toHaveCount(0);
        const next=await request('show',dialog().getByRole('button',{name:'Open replacement plan',exact:true}));assert.equal(next.plan_hash,replacement.plan_hash);
      });
      await mark('replacement-consent',async()=>{
        const doc=await request('review',dialog().getByRole('button',{name:'Mark this plan reviewed',exact:true}));
        assert.equal(doc.plan_hash,replacement.plan_hash);await expect(dialog().getByRole('checkbox').nth(0)).not.toBeChecked();
        await expect(dialog().getByRole('checkbox').nth(1)).not.toBeChecked();replacement=await approve();
      });
      await mark('readback',async()=>{const doc=await request('show',dialog().getByRole('button',{name:'Refresh saved plan',exact:true}));assert.deepEqual(doc,replacement);});
      await mark('close-focus',async()=>{await close(true);await open();await close();});
      await mark('reload',async()=>{
        await select();await open();await click(dialog().locator('summary').filter({hasText:'Open an existing plan'}));
        await get('Saved plan hash').fill(replacement.plan_hash);
        assert.deepEqual(await request('show',dialog().getByRole('button',{name:'Show saved plan',exact:true})),replacement);
        await showPhase('approved');
      });
      await page.screenshot({path:join(c.output,`plan-readback-${pointer}-${width}.png`)});
      if(width===1440&&pointer==='fine'){
        stage='pending-write-close';report.stage=stage;await save();
        // Hold one genuine server response after commit; no fake response bytes or second server invocation.
        await click(dialog().getByRole('button',{name:'Edit plan',exact:true}));
        await get('Private body').fill(JSON.stringify({description:secrets[0]+'-pending-close'}));
        let release,committedResolve,committedReject;
        const held=new Promise(resolve=>{release=resolve;});
        const committed=new Promise((resolve,reject)=>{committedResolve=resolve;committedReject=reject;});
        const url=c.origin+'/api/v1/exercise/plans/'+replacement.plan_hash+'/edit';
        await page.route(url,async route=>{
          try{assert.equal(route.request().method(),'POST');assert.equal(route.request().url(),url);
            const response=await route.fetch({timeout:8000,maxRedirects:0,maxRetries:0});assert.equal(response.status(),200);
            committedResolve();await held;await route.fulfill({response});}
          catch(error){committedReject(error);await route.abort();}
        });
        const finished=request('edit',dialog().getByRole('button',{name:'Save replacement plan',exact:true}));
        try{await committed;await close(true);}finally{release();}
        const saved=await finished;await page.unroute(url);
        await expect(opener).not.toHaveAttribute('aria-disabled','true');await open();
        await expect(get('Saved plan hash')).toHaveValue(saved.plan_hash);
        const confirmed=await request('show',dialog().getByRole('button',{name:'Show saved plan',exact:true}));
        assert.deepEqual(confirmed,saved);assert.equal(saved.phase.phase,'draft');assert.equal(saved.supersedes,replacement.plan_hash);
        report.pendingWriteClose='passed';await save();
        // A new ordinary local plan with actual server TTL; the application remains stopped behind its listener.
        stage='server-expiry';report.stage=stage;await save();await close();await select();await open();
        await get('Catalog revision ID').fill(c.revisionId);await get('Operation version ID').fill(c.operationVersionId);
        await get('Loopback HTTP origin with port').fill(c.target);await get('I own this local development application.').check();
        await get('Plan lifetime in seconds').fill('5');await get('Body source').selectOption('empty_by_operator');
        const short=await request('create',dialog().getByRole('button',{name:'Create private plan',exact:true}));
        assert.equal(short.expires_at-short.created_at,5);
        const reviewed=await request('review',dialog().getByRole('button',{name:'Mark this plan reviewed',exact:true}));
        assert.equal(reviewed.ready_for_approval,true);await expect(dialog().getByRole('button',{name:'Save item approval',exact:true})).toBeDisabled();
        // Synchronize on the real UI's expiry timer, without changing either clock or sleeping/retrying.
        await expect(dialog().getByText('The plan has expired.',{exact:true})).toBeVisible({timeout:8000});
        const expired=await request('show',dialog().getByRole('button',{name:'Refresh saved plan',exact:true}),{expired:true});
        assert.equal(expired.plan_hash,short.plan_hash);assert.equal(expired.ready_for_approval,false);assert.equal(expired.phase.phase,'reviewed');
        await expect(dialog().getByRole('button',{name:'Save item approval',exact:true})).toHaveCount(0);
        await expect(dialog().getByRole('button',{name:'Mark this plan reviewed',exact:true})).toHaveCount(0);
        await expect(dialog().getByText('The plan has expired.',{exact:true})).toBeVisible();
        report.expiry='server-expired-and-approval-unavailable';report.serverExpiredDrafts=1;await save();
      }
      await mark('private-persistence',async()=>{
        const storage=await page.evaluate(async()=>({local:JSON.stringify(localStorage),session:JSON.stringify(sessionStorage),
          indexed:typeof indexedDB.databases==='function'?(await indexedDB.databases()).map(x=>x.name):[],caches:await caches.keys()}));
        assert.ok(!leaks(JSON.stringify(storage)));assert.equal(storage.indexed.length,0);assert.equal(storage.caches.length,0);
        assert.equal(report.privateLeaks,0);
      });
      await mark('no-external-requests',async()=>{
        const assertQuiet = () => {
          assert.equal(external,0);assert.equal(unexpectedWrites,0);assert.equal(downloads,0);
          assert.equal(errorCount,0);assert.equal(report.privateLeaks,0);
        };
        assertQuiet();
        await close();await context.close();
        assertQuiet();
      });
      cell.status='passed';await save();
    } catch(error){report.externalRequests+=external;report.consoleErrors+=errorCount;report.downloads+=downloads;
      cell.status='failed';if(Object.hasOwn(cell.checks,stage))cell.checks[stage]='failed';await save();await context.close();throw error;}
    report.externalRequests+=external;report.consoleErrors+=errorCount;report.downloads+=downloads;
  }
  assert.deepEqual(report.routes,{create:11,edit:21,show:42,review:31,approve:20});assert.deepEqual(report.observedRoutes,report.routes);assert.equal(privateDocs.length,125);
  assert.equal(report.cells.length,10);assert.equal(report.serverExpiredDrafts,1);assert.equal(report.expiry,'server-expired-and-approval-unavailable');assert.ok(report.cells.every(x=>x.status==='passed'&&Object.values(x.checks).every(v=>v==='passed')));
  report.status='passed';report.stage='complete';
} catch {
  report.status='failed';report.stage=(checks.includes(stage)||stage==='pending-write-close'||stage==='server-expiry')?stage:'bootstrap';
  process.exitCode=1;
} finally {
  await browser.close();await writeFile(join(c.output,'documents.private.json'),JSON.stringify(privateDocs)+'\n',{mode:0o600});await save();
}
