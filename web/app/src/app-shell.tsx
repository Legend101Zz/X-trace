import { useLayoutEffect, useRef, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import { useThemePreference } from './theme-preference';
import type { AuthState, Detail, Endpoint, Pane, ReplayEvent } from './types';
import { RecordingTabs } from './features/shell/RecordingTabs';
import type { OpenRecording } from './features/shell/RecordingTabs';
import type { InspectorDock } from './features/shell/ResizableWorkspace';
import { useViewport } from './features/shell/viewport';
import { ResizableWorkspace } from './features/shell/ResizableWorkspace';
import { RecordingContext } from './features/shell/RecordingContext';
import { ViewerDialog } from './features/shell/ViewerDialog';
import { ViewerHelp } from './features/shell/ViewerHelp';
import { ViewerSettings } from './features/shell/ViewerSettings';
import { useAppearancePreferences, ViewerPreferencesContext } from './features/shell/viewer-preferences';
import './features/shell/viewer-dialog.css';

const INSPECTOR_DOCK_KEY = 'xtrace.viewer.inspector-dock';

function readInspectorDock(): InspectorDock {
  try {
    return window.localStorage.getItem(INSPECTOR_DOCK_KEY) === 'right' ? 'right' : 'bottom';
  } catch {
    return 'bottom';
  }
}

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
  const [dock, setDock] = useState(readInspectorDock);
  const theme = useThemePreference();
  const appearance = useAppearancePreferences();
  const [modal, setModal] = useState<{ title: 'Settings' | 'Help'; opener: HTMLElement } | null>(null);
  function changeDock(next: InspectorDock) {
    setDock(next);
    try { window.localStorage.setItem(INSPECTOR_DOCK_KEY, next); } catch {
      // The preference still applies to the current viewer.
    }
  }
  const requestsDrawer = useViewport('(min-width: 861px) and (max-width: 1199px)');
  const previousPane = useRef(activePane);
  useLayoutEffect(() => {
    const wasOpen = previousPane.current === 'recordings';
    previousPane.current = activePane;
    if (!requestsDrawer || !wasOpen || activePane === 'recordings') return;
    const focus = document.activeElement;
    if (focus === document.body || focus?.closest('#recordings-panel')) {
      const tab = document.getElementById(`open-recording-${selectedRecording}`);
      (tab ?? document.getElementById('header-requests'))?.focus();
    }
  }, [activePane, requestsDrawer, selectedRecording]);

  const closeRequests = () => {
    onPane('events');
    document.getElementById('header-requests')?.focus();
  };
  return <ViewerPreferencesContext.Provider value={appearance.preferences}>
    <div className="shell viewer-shell" data-pane={activePane} data-reading={detail !== null && sourceEvent !== undefined}
      data-density={appearance.preferences.density} data-motion={appearance.preferences.motion}
      style={{ '--viewer-code-size': `${appearance.preferences.codeSize}px` } as CSSProperties}
    onKeyDown={(event) => {
      if (requestsDrawer && activePane === 'recordings' && event.key === 'Escape') {
        event.preventDefault();
        closeRequests();
      }
    }}>
    <header className="topbar">
      <button type="button" id="header-requests" className="button header-requests"
        aria-controls="recordings-panel" aria-expanded={activePane === 'recordings'} onClick={() => {
        if (requestsDrawer && activePane === 'recordings') {
          closeRequests();
          return;
        }
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
    <ResizableWorkspace requests={children[0]} steps={children[1]} inspector={children[2]} sourceEvent={sourceEvent} activePane={activePane} dock={dock} />
    <footer className="viewer-preferences">
      <span>{auth === 'ready' ? 'Local viewer connected' : auth === 'checking' ? 'Connecting to local viewer' : 'Local viewer unavailable'}</span>
      <div className="viewer-dialog-actions">
        {(['Settings', 'Help'] as const).map((title) => <button type="button" className="button" key={title}
          aria-haspopup="dialog" onClick={(event) => setModal({ title, opener: event.currentTarget })}>{title}</button>)}
      </div>
    </footer>
    <div className="sr-only" role="status" aria-live="polite">{announcement}</div>
    {auth === 'checking' ? <div className="sr-only" role="status">Authenticating viewer link</div> : null}
    {auth === 'expired' ? <div role="alert" className="auth-overlay"><div><strong>Viewer session expired</strong><p>Restart the foreground viewer to create a new one-time link.</p></div></div> : null}
    {auth === 'error' ? <div role="alert" className="auth-overlay"><div><strong>Viewer authentication failed</strong><p>{authError}</p></div></div> : null}
    </div>
    {modal ? <ViewerDialog title={modal.title} opener={modal.opener} onClose={() => setModal(null)}>
      {modal.title === 'Settings' ? <ViewerSettings appearance={appearance} theme={theme} dock={dock} onDock={changeDock} />
        : <ViewerHelp />}
    </ViewerDialog> : null}
  </ViewerPreferencesContext.Provider>;
}
