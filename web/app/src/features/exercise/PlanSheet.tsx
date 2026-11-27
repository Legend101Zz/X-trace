import { useEffect, useRef, useState } from 'react';
import { editDraft, missingCreateReceipt, planRequest, UnconfirmedPlanResult } from './client';
import type { Binding, Draft, Review } from './client';
import { PlanFields } from './PlanFields';
import { PlanReview } from './PlanReview';

function blank(binding: Binding): Draft {
  return { revision_id: '', selected_operation_version_id: '', operation_id: binding.operation, recording_id: binding.recording,
    target: { base_url: '', operator_owned_development: false }, inputs: [], body: { source: 'not_recorded' }, lifetime_seconds: 600 };
}

export function PlanSheet({ binding, lastHash, remember, onWrite, missingReceipt, onMissingReceipt }: {
  missingReceipt?: boolean; onMissingReceipt?: () => void;
  binding: Binding; lastHash: string; remember: (hash: string) => void; onWrite: (busy: boolean) => void;
}) {
  const [draft, setDraft] = useState<Draft | null>(() => lastHash ? null : blank(binding));
  const [doc, setDoc] = useState<Review | null>(null);
  const [lookup, setLookup] = useState(lastHash);
  const [error, setError] = useState(missingReceipt ? missingCreateReceipt : '');
  const [needsRefresh, setNeedsRefresh] = useState(false);
  const [consent, setConsent] = useState(false);
  const [owned, setOwned] = useState(false);
  const [busy, setBusy] = useState(false);
  const [clockExpired, setClockExpired] = useState(false);
  const pending = useRef<AbortController | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const focusAfterChange = useRef(false);
  const mounted = useRef(true);
  const reading = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      // A committed write can outlive its dialog. Retain only the confirmed hash on close.
      if (reading.current) pending.current?.abort();
    };
  }, []);
  useEffect(() => {
    if (!doc) return;
    const delay = doc.expires_at * 1000 - Date.now();
    setClockExpired(delay <= 0);
    if (delay > 0) {
      const timer = window.setTimeout(() => setClockExpired(true), Math.min(delay, 2 ** 31 - 1));
      return () => window.clearTimeout(timer);
    }
  }, [doc]);
  useEffect(() => {
    if (focusAfterChange.current) {
      heading.current?.focus();
      focusAfterChange.current = false;
    }
  }, [doc, draft === null]);
  function clearConsent() { setConsent(false); setOwned(false); }
  async function act(operation: Parameters<typeof planRequest>[1]) {
    if (pending.current) return;
    const abort = new AbortController();
    reading.current = operation.action === 'show';
    if (!reading.current) onWrite(true);
    pending.current = abort;
    setBusy(true); setError(''); clearConsent();
    try {
      const next = await planRequest(binding, operation, abort.signal);
      if (abort.signal.aborted) return;
      remember(next.plan_hash);
      if (!mounted.current) return;
      setLookup(next.plan_hash);
      setNeedsRefresh(false);
      setClockExpired(Date.now() >= next.expires_at * 1000);
      focusAfterChange.current = true;
      setDoc(next); setDraft(null);
    } catch (problem) {
      if (operation.action === 'create' && problem instanceof UnconfirmedPlanResult) onMissingReceipt?.();
      if (mounted.current && !abort.signal.aborted) {
        setError(problem instanceof Error ? problem.message : 'The local viewer could not confirm this action.');
        if ('previous' in operation && operation.action !== 'show') setNeedsRefresh(true);
      }
    } finally {
      if (pending.current === abort) pending.current = null;
      if (operation.action !== 'show') onWrite(false);
      if (mounted.current && !abort.signal.aborted) setBusy(false);
    }
  }
  const phase = doc?.phase.phase;
  const expired = Boolean(doc?.expired || clockExpired);
  const active = !expired && phase !== 'superseded' && phase !== 'consumed';
  const item = doc?.preview.items[0];
  const restore = <form className="plan-restore" autoComplete="off" onSubmit={e => {
    e.preventDefault(); void act({ action: 'show', previous: lookup });
  }}>
    <label>Saved plan hash<input autoCapitalize="none" spellCheck={false} required maxLength={64}
      value={lookup} onChange={e => setLookup(e.target.value)} /></label>
    <button type="submit" className="button" disabled={busy}>Show saved plan</button>
  </form>;
  return <div className="plan-sheet" aria-busy={busy} spellCheck={false}>
    <h3 tabIndex={-1} ref={heading}>{draft ? (doc ? 'Edit plan' : 'Plan') : doc ? 'Review' : 'Saved plan'}</h3>
    <p className="plan-observed"><strong>{binding.method} {binding.route}</strong> · Observed endpoint</p>
    <p>Private plan for your local application. These controls send zero application requests.</p>
    {error && <p className="plan-error" role="alert">{error}</p>}
    {busy && <p>Waiting for the local viewer…</p>}
    {draft ? <>
      {doc && <p>Saving an edit replaces the plan and revokes its approval. The original remains in effect until the replacement is saved.</p>}
      <form autoComplete="off" onSubmit={e => {
        e.preventDefault();
        if (!needsRefresh) void act(doc ? { action: 'edit', previous: doc.plan_hash, draft } : { action: 'create', draft });
      }}><fieldset className="plan-fields" disabled={busy}>
        <PlanFields draft={draft} onChange={setDraft} />
        <div className="plan-actions">
          <button className="button plan-primary" type="submit" disabled={needsRefresh}>{doc ? 'Save replacement plan' : 'Create private plan'}</button>
          {doc && <button className="button" type="button" onClick={() => {
            setDraft(null); clearConsent(); setError(''); focusAfterChange.current = true;
          }}>Discard edits</button>}
        </div>
      </fieldset></form>
      {needsRefresh && doc && <button className="button" disabled={busy} onClick={() => void act({ action: 'show', previous: doc.plan_hash })}>Refresh saved plan</button>}
      {!doc && <details><summary>Open an existing plan</summary>{restore}</details>}
    </> : doc && item ? <>
      <PlanReview doc={doc} />
      {expired && phase !== 'superseded' && phase !== 'consumed' && <p>The plan has expired.</p>}
      {phase === 'superseded' && <p>Superseded. Its previous approval is revoked.</p>}
      {phase === 'reviewed' && !doc.ready_for_approval && active && <p>Approval is unavailable. Check missing inputs and the request body.</p>}
      {phase === 'reviewed' && doc.ready_for_approval && active && !needsRefresh && <fieldset disabled={busy}><legend>Item approval</legend>
        <label className="plan-check"><input type="checkbox" checked={owned} onChange={e => setOwned(e.target.checked)} />
          I confirm that {doc.target.base_url} is my local development application.</label>
        <label className="plan-check"><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} />
          I approve {item.request} with the inputs, effect and plan hash shown above.</label>
        <button className="button plan-primary" disabled={!owned || !consent}
          onClick={() => void act({ action: 'approve', previous: doc.plan_hash, planId: doc.plan_id, item: item.item_id })}>Save item approval</button>
      </fieldset>}
      <div className="plan-actions">
        {active && !needsRefresh && phase === 'draft' && <button className="button plan-primary" disabled={busy}
          onClick={() => void act({ action: 'review', previous: doc.plan_hash })}>Mark this plan reviewed</button>}
        {active && !needsRefresh && <button className="button" disabled={busy} onClick={() => {
          clearConsent(); setError(''); focusAfterChange.current = true; setDraft(editDraft(doc));
        }}>Edit plan</button>}
        <button className="button" disabled={busy} onClick={() => void act({ action: 'show', previous: doc.plan_hash })}>Refresh saved plan</button>
        {phase === 'superseded' && doc.phase.replacement_hash && <button className="button" disabled={busy}
          onClick={() => void act({ action: 'show', previous: doc.phase.replacement_hash! })}>Open replacement plan</button>}
        {!active && <button className="button" disabled={busy} onClick={() => {
          clearConsent(); setError(''); setNeedsRefresh(false); setDoc(null); setDraft(blank(binding)); focusAfterChange.current = true;
        }}>Start a new draft</button>}
      </div>
    </> : restore}
  </div>;
}
