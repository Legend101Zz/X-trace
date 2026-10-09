import { navigationControls } from '../../replay/navigation';
import type { NavAction, NavFrameNavigation } from '../../replay/navigation';

export interface NavigationControlsProps {
  navigation: NavFrameNavigation | null | undefined;
  loadedFrameIds: ReadonlySet<string>;
  onNavigate: (action: NavAction, frameId: string) => void;
}

export function NavigationControls({ navigation, loadedFrameIds, onNavigate }: NavigationControlsProps) {
  const controls = navigationControls(navigation, loadedFrameIds);
  return <div className="inspector-section nav-controls" role="group" aria-label="Frame navigation">
    <div className="inspector-label">Frame navigation</div>
    <div className="nav-buttons">
      {controls.map((control) => <button key={control.action} className="button" disabled={!control.enabled}
        aria-describedby={control.reason ? `nav-reason-${control.action}` : undefined}
        onClick={() => control.targetFrameId && onNavigate(control.action, control.targetFrameId)}>{control.label}</button>)}
    </div>
    {controls.filter((control) => control.reason).map((control) => <div key={control.action} id={`nav-reason-${control.action}`} className="evidence-state">{control.label}: {control.reason}</div>)}
  </div>;
}
