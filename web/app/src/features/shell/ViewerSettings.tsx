import { ThemeControl } from '../../theme-preference';
import type { useThemePreference } from '../../theme-preference';
import { CODE_SIZES } from './viewer-preferences';
import type { useAppearancePreferences } from './viewer-preferences';
import type { InspectorDock } from './ResizableWorkspace';

export function ViewerSettings({ appearance, theme, dock, onDock }: {
  appearance: ReturnType<typeof useAppearancePreferences>;
  theme: ReturnType<typeof useThemePreference>;
  dock: InspectorDock;
  onDock: (dock: InspectorDock) => void;
}) {
  const { preferences, update } = appearance;
  return <>
    <section><h3>Appearance</h3>
      <ThemeControl {...theme} />
      <label>Code font size
        <select className="theme-select" value={preferences.codeSize} onChange={(event) => {
          const next = CODE_SIZES.find((size) => size === event.currentTarget.value);
          if (next) update('codeSize', next);
        }}>
          {CODE_SIZES.map((size) => <option key={size} value={size}>{size} px</option>)}
        </select>
      </label>
      <label>Density
        <select className="theme-select" value={preferences.density}
          onChange={(event) => update('density', event.currentTarget.value === 'compact' ? 'compact' : 'comfortable')}>
          <option value="comfortable">Comfortable</option><option value="compact">Compact</option>
        </select>
      </label>
      <p>Compact shortens rows on a desktop with a fine pointer. Touch targets stay at least 44 px.</p>
    </section>
    <section><h3>Replay</h3>
      <label>Show timing
        <select className="theme-select" value={preferences.timing}
          onChange={(event) => update('timing', event.currentTarget.value === 'on' ? 'on' : 'off')}>
          <option value="on">On</option><option value="off">Off</option>
        </select>
      </label>
      <p>Time since the first loaded step, from recorded monotonic timestamps. This is not a step duration.</p>
      <label>Inline values in code
        <select className="theme-select" value={preferences.inline}
          onChange={(event) => update('inline', event.currentTarget.value === 'off' ? 'off' : 'on')}>
          <option value="on">On</option><option value="off">Off</option>
        </select>
      </label>
    </section>
    <section><h3>Time</h3>
      <label>Recording times
        <select className="theme-select" value={preferences.time}
          onChange={(event) => update('time', event.currentTarget.value === 'utc' ? 'utc' : 'local')}>
          <option value="local">Local</option><option value="utc">UTC</option>
        </select>
      </label>
    </section>
    <section><h3>Layout</h3>
      <label>Inspector dock
        <select className="theme-select" value={dock}
          onChange={(event) => onDock(event.currentTarget.value === 'right' ? 'right' : 'bottom')}>
          <option value="bottom">Bottom</option><option value="right">Right</option>
        </select>
      </label>
      <p>This setting applies to the desktop layout.</p>
    </section>
    <section><h3>Motion</h3>
      <label>Animations
        <select className="theme-select" value={preferences.motion}
          onChange={(event) => update('motion', event.currentTarget.value === 'reduce' ? 'reduce' : 'system')}>
          <option value="system">Follow system</option><option value="reduce">Reduce motion</option>
        </select>
      </label>
    </section>
    <p>Settings are saved in this browser when storage is available. Otherwise, changes apply to this session.</p>
  </>;
}
