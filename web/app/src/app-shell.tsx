import type { ReactNode } from 'react';
import type { AuthState, Pane } from './types';

const PANES = ['recordings', 'events', 'evidence'] as const;

export interface AppShellProps {
  activePane: Pane;
  onPane: (pane: Pane) => void;
  announcement: string;
  auth: AuthState;
  authError: string;
  children: ReactNode;
}

/** Page chrome: header, pane tabs, live region and authentication overlays. */
export function AppShell({ activePane, onPane, announcement, auth, authError, children }: AppShellProps) {
  return <div className="shell">
    <header className="topbar">
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
      {PANES.map((pane) => <button key={pane} role="tab" id={`${pane}-tab`} aria-controls={`${pane}-panel`} tabIndex={activePane === pane ? 0 : -1} className="pane-tab" aria-selected={activePane === pane} onClick={() => onPane(pane)}>{pane}</button>)}
    </nav>
    <main className="workspace">
      {children}
    </main>
    <div className="sr-only" role="status" aria-live="polite">{announcement}</div>
    {auth === 'checking' ? <div className="sr-only" role="status">Authenticating viewer link</div> : null}
    {auth === 'expired' ? <div role="alert" className="auth-overlay"><div><strong>Viewer session expired</strong><p>Restart the foreground viewer to create a new one-time link.</p></div></div> : null}
    {auth === 'error' ? <div role="alert" className="auth-overlay"><div><strong>Viewer authentication failed</strong><p>{authError}</p></div></div> : null}
  </div>;
}
