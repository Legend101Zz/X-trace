import { useContext, useId, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { TourPane } from '../shell/ViewerTour';
import { useViewport } from '../shell/viewport';
import type { NavAction } from '../../replay/navigation';
import { missingEvidence } from '../../replay/missing';
import type { MissingTarget } from '../../replay/missing';
import { CodeEvidence } from '../code/CodeEvidence';
import { backToStepLabel } from '../../replay/step-sentence';
import { Values } from './Values';
import { Missing } from './Missing';
import { EvidenceDetails } from './EvidenceDetails';
import type { Detail, ReplayEvent } from '../../types';
import './inspector-tabs.css';

const DESKTOP_TABS = ['Values', 'Missing', 'Details'] as const;
const READING_TABS = ['Code', ...DESKTOP_TABS] as const;
type Tab = (typeof READING_TABS)[number];

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
  const tourPane = useContext(TourPane);
  const hasCodePane = useViewport('(min-width: 861px)');
  const readingViewport = useViewport('(max-width: 860px)');
  const tabs = readingViewport ? READING_TABS : DESKTOP_TABS;
  const [choice, setChoice] = useState<Tab>(() => hasCodePane ? 'Values' : 'Details');
  const checksEvidence = tourPane === 'evidence';
  const [tourChoice, setTourChoice] = useState<Tab | null>(null);
  const requested = checksEvidence ? tourChoice ?? (event ? 'Missing' : choice) : choice;
  const tab = !readingViewport && requested === 'Code' ? (hasCodePane ? 'Values' : 'Details') : requested;
  function chooseTab(label: Tab) {
    setChoice(label);
    if (checksEvidence) setTourChoice(label);
  }
  const content = useRef<HTMLDivElement>(null);
  const prefix = useId();
  const reports = useMemo(() => detail ? missingEvidence(detail) : null, [detail]);
  useLayoutEffect(() => { if (hasCodePane) setChoice('Values'); }, [hasCodePane]);

  useLayoutEffect(() => {
    if (readingViewport && active && event?.sequence !== undefined) setChoice('Code');
  }, [active, detail?.recordingId, event?.sequence, readingViewport]);

  // Each visit to the last guide step starts at Missing. During that visit the
  // reader owns the tab, even as normal pane and event updates select defaults.
  useLayoutEffect(() => { if (!checksEvidence) setTourChoice(null); }, [checksEvidence]);

  useLayoutEffect(() => { if (content.current) content.current.scrollTop = 0; }, [tab, event?.sequence, detail?.recordingId, active]);

  const renderCode = () => event ? <section className="inspector-section" aria-label="Code">
    <h2 className="inspector-label">Recorded source evidence</h2>
    <CodeEvidence event={event} />
  </section> : <p className="evidence-state">{selectionUnavailable ?? 'Select an event for source evidence.'}</p>;

  return <section className="pane evidence-pane" role="tabpanel" id="evidence-panel" aria-labelledby="evidence-tab" data-active={active} aria-label="Evidence inspector">
    <div className="pane-head"><div><div className="eyebrow">Persisted facts</div><h1>Evidence inspector</h1></div><span className="top-meta">{currentStatus}</span></div>
    {event ? <button type="button" className={`button ${readingViewport ? 'button-primary phone-back-to-step' : 'wide-focus-event'}`}
      onClick={onBackToEvent}>{readingViewport ? backToStepLabel(event) : `Focus event ${event.sequence}`}</button> : null}
    {detail && reports ? <div className="inspector-tabs" role="tablist" aria-label="Inspector evidence" onKeyDown={(event) => {
      const index = tabs.findIndex((label) => label === tab);
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1
        : event.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length
          : event.key === 'ArrowRight' ? (index + 1) % tabs.length : null;
      if (next === null || event.altKey || event.ctrlKey || event.metaKey) return;
      event.preventDefault();
      const label = tabs[next];
      chooseTab(label);
      document.getElementById(`${prefix}-tab-${label}`)?.focus();
    }}>
      {tabs.map((label) => <button type="button" className="button" key={label}
        id={`${prefix}-tab-${label}`} role="tab" aria-selected={tab === label} tabIndex={tab === label ? 0 : -1}
        aria-controls={`${prefix}-panel-${label}`} onClick={() => chooseTab(label)}>
        {label}{label === 'Values' && event ? ` (${event.bindings?.length ?? 0})` : null}
        {label === 'Missing' ? ` (${reports.window.length})` : null}
      </button>)}
    </div> : null}
    <div className="inspector evidence-content" ref={content}>
      {!hasCodePane && !readingViewport && event ? renderCode() : null}
      {detail && reports ? tabs.map((label) => <div key={label} id={`${prefix}-panel-${label}`} role="tabpanel"
        aria-labelledby={`${prefix}-tab-${label}`} hidden={tab !== label}>
        {tab === label && label === 'Code' ? renderCode() : null}
        {tab === label && label === 'Values' ? event ? <Values bindings={event.bindings ?? []} />
          : <p className="evidence-state">{selectionUnavailable ?? 'Select an event for recorded bindings.'}</p> : null}
        {tab === label && label === 'Missing' ? <Missing {...reports} onGoTo={onGoToMissing} /> : null}
        {tab === label && label === 'Details'
          ? <EvidenceDetails detail={detail} event={event} selectionUnavailable={selectionUnavailable} showSourceExplanation={hasCodePane || readingViewport} onNavigate={onNavigate} /> : null}
      </div>) : <div className="empty"><strong>Select an event</strong><p>Event selection synchronizes this evidence inspector.</p></div>}
      {event ? <p className="evidence-state">response outcome is not event-verified</p> : null}
    </div>
  </section>;
}
