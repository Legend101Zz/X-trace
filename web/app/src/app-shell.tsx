import type { ReactNode } from 'react';
import { ThemePreference } from './theme-preference';
import type { AuthState, Detail, Endpoint, Pane, ReplayEvent } from './types';
import { RecordingTabs } from './features/shell/RecordingTabs';
import type { OpenRecording } from './features/shell/RecordingTabs';
import { ResizableWorkspace } from './features/shell/ResizableWorkspace';
import { RecordingContext } from './features/shell/RecordingContext';

const PANES = ['recordings', 'events', 'evidence'] as const;
const PANE_LABELS = { recordings: 'Requests', events: 'Steps', evidence: 'Inspector' } as const;

export interface AppShellProps {
  activePane: Pane;
  onPane: (pane: Pane) => void;
  announcement: string;
  auth: AuthState;
  authError: string;
  openRecordings: readonly OpenRecording[];
  selectedRecording: string;
  onSelectRecording: (id: string) => void;
  onCloseRecording: (id: string) => void;
  sourceEvent: ReplayEvent | undefined;
  detail: Detail | null;
  endpoint: Endpoint | null;
  children: [ReactNode, ReactNode, ReactNode];
}

/** Page chrome: header, pane tabs, live region and authentication overlays. */
export function AppShell({ activePane, onPane, announcement, auth, authError, openRecordings, selectedRecording, onSelectRecording, onCloseRecording, sourceEvent, detail, endpoint, children }: AppShellProps) {
  return <div className="shell viewer-shell" data-pane={activePane} data-reading={detail !== null && sourceEvent !== undefined}>
    <header className="topbar">
      <button type="button" className="button header-requests" onClick={() => {
        onPane('recordings');
        requestAnimationFrame(() => document.getElementById('request-search')?.focus());
      }}>Requests</button>
      <div className="brand"><span className="brand-mark">X/</span><span>X-trace</span><span className="top-meta">local recording viewer</span></div>
      <div className="top-meta">experimental · read only</div>
    </header>
    <nav className="tabs" role="tablist" aria-label="Viewer panes" onKeyDown={(keyboard) => {
      if (keyboard.key !== 'ArrowRight' && keyboard.key !== 'ArrowLeft') return;
      keyboard.preventDefault();
      const direction = keyboard.key === 'ArrowRight' ? 1 : -1;
      const next = PANES[(PANES.indexOf(activePane) + direction + PANES.length) % PANES.length];
      onPane(next);
      document.getElementById(`${next}-tab`)?.focus();
    }}>
      {PANES.map((pane) => <button key={pane} role="tab" id={`${pane}-tab`} aria-controls={`${pane}-panel`} tabIndex={activePane === pane ? 0 : -1} className="pane-tab" aria-selected={activePane === pane} onClick={() => onPane(pane)}>{PANE_LABELS[pane]}</button>)}
    </nav>
    <RecordingTabs recordings={openRecordings} selected={selectedRecording} onSelect={onSelectRecording} onClose={onCloseRecording} />
    {detail ? <RecordingContext key={detail.recordingId} detail={detail} endpoint={endpoint} event={sourceEvent} /> : null}
    <ResizableWorkspace requests={children[0]} steps={children[1]} inspector={children[2]} sourceEvent={sourceEvent} activePane={activePane} />
    <footer className="viewer-preferences">
      <span>{auth === 'ready' ? 'Local viewer connected' : auth === 'checking' ? 'Connecting to local viewer' : 'Local viewer unavailable'}</span>
      <ThemePreference />
    </footer>
    <div className="sr-only" role="status" aria-live="polite">{announcement}</div>
    {auth === 'checking' ? <div className="sr-only" role="status">Authenticating viewer link</div> : null}
    {auth === 'expired' ? <div role="alert" className="auth-overlay"><div><strong>Viewer session expired</strong><p>Restart the foreground viewer to create a new one-time link.</p></div></div> : null}
    {auth === 'error' ? <div role="alert" className="auth-overlay"><div><strong>Viewer authentication failed</strong><p>{authError}</p></div></div> : null}
  </div>;
}
