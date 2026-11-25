import { useId, useMemo, useState } from 'react';
import { useViewport } from '../shell/viewport';
import type { NavAction } from '../../replay/navigation';
import { missingEvidence } from '../../replay/missing';
import type { MissingTarget } from '../../replay/missing';
import { CodeEvidence } from '../code/CodeEvidence';
import { Values } from './Values';
import { Missing } from './Missing';
import { EvidenceDetails } from './EvidenceDetails';
import type { Detail, ReplayEvent } from '../../types';
import './inspector-tabs.css';

const TABS = ['Values', 'Missing', 'Details'] as const;
type Tab = (typeof TABS)[number];

export interface EvidencePanelProps {
  active: boolean;
  currentStatus: string;
  detail: Detail | null;
  event: ReplayEvent | undefined;
  selectionUnavailable: string | null;
  onBackToEvent: () => void;
  onNavigate: (action: NavAction, frameId: string) => void;
  onGoToMissing: (target: MissingTarget) => void;
}

export function EvidencePanel({ active, currentStatus, detail, event, selectionUnavailable, onBackToEvent, onNavigate, onGoToMissing }: EvidencePanelProps) {
  const hasCodePane = useViewport('(min-width: 861px)');
  const [tab, setTab] = useState<Tab>('Details');
  const prefix = useId();
  const reports = useMemo(() => detail ? missingEvidence(detail) : null, [detail]);
  return <section className="pane" role="tabpanel" id="evidence-panel" aria-labelledby="evidence-tab" data-active={active} aria-label="Evidence inspector">
    <div className="pane-head"><div><div className="eyebrow">Persisted facts</div><h1>Evidence inspector</h1></div><span className="top-meta">{currentStatus}</span></div>
    {event ? <button type="button" className="button button-primary phone-back-to-step" onClick={onBackToEvent}>Back to event {event.sequence}</button> : null}
    <div className="inspector">
      {!hasCodePane && event ? <section className="inspector-section" aria-label="Code">
        <h2 className="inspector-label">Recorded source evidence</h2>
        <CodeEvidence event={event} />
      </section> : null}
      {event ? <p className="evidence-state">response outcome is not event-verified</p> : null}
      {detail && reports ? <>
        <div className="inspector-tabs" role="tablist" aria-label="Inspector evidence" onKeyDown={(event) => {
          const index = TABS.indexOf(tab);
          const next = event.key === 'Home' ? 0 : event.key === 'End' ? TABS.length - 1
            : event.key === 'ArrowLeft' ? (index + TABS.length - 1) % TABS.length
              : event.key === 'ArrowRight' ? (index + 1) % TABS.length : null;
          if (next === null || event.altKey || event.ctrlKey || event.metaKey) return;
          event.preventDefault();
          const label = TABS[next];
          setTab(label);
          document.getElementById(`${prefix}-tab-${label}`)?.focus();
        }}>
          {TABS.map((label) => <button type="button" className="button" key={label}
            id={`${prefix}-tab-${label}`} role="tab" aria-selected={tab === label} tabIndex={tab === label ? 0 : -1}
            aria-controls={`${prefix}-panel-${label}`} onClick={() => setTab(label)}>
            {label}{label === 'Values' && event ? ` (${event.bindings?.length ?? 0})` : null}
            {label === 'Missing' ? ` (${reports.window.length})` : null}
          </button>)}
        </div>
        {TABS.map((label) => <div key={label} id={`${prefix}-panel-${label}`} role="tabpanel"
          aria-labelledby={`${prefix}-tab-${label}`} hidden={tab !== label}>
          {tab === label && label === 'Values' ? event ? <Values bindings={event.bindings ?? []} />
            : <p className="evidence-state">{selectionUnavailable ?? 'Select an event for recorded bindings.'}</p> : null}
          {tab === label && label === 'Missing' ? <Missing {...reports} onGoTo={onGoToMissing} /> : null}
          {tab === label && label === 'Details'
            ? <EvidenceDetails detail={detail} event={event} selectionUnavailable={selectionUnavailable} showSourceExplanation={hasCodePane} onNavigate={onNavigate} /> : null}
        </div>)}
      </> : <div className="empty"><strong>Select an event</strong><p>Event selection synchronizes this evidence inspector.</p></div>}
    </div>
  </section>;
}
