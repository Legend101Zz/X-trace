import { useId, useRef, useState } from 'react';
import honesty from '../../../../../schema/fixtures/replay/honesty-strings.json';

const sections = ['Glossary', 'Keyboard', 'Layout'] as const;

export function ViewerHelp() {
  const [active, setActive] = useState(0);
  const prefix = useId();
  const tabList = useRef<HTMLDivElement>(null);
  return <>
    <div className="viewer-help-tabs" ref={tabList} role="tablist" aria-label="Help topics" onKeyDown={(event) => {
      const key = event.key;
      const next = key === 'Home' ? 0 : key === 'End' ? sections.length - 1
        : key === 'ArrowRight' ? (active + 1) % sections.length
        : key === 'ArrowLeft' ? (active + sections.length - 1) % sections.length : null;
      if (next === null) return;
      event.preventDefault();
      setActive(next);
      tabList.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
    }}>
      {sections.map((section, index) => <button key={section} type="button" role="tab" className="button"
        id={`${prefix}-tab-${index}`} aria-controls={`${prefix}-panel-${index}`}
        aria-selected={active === index} tabIndex={active === index ? 0 : -1} onClick={() => setActive(index)}>{section}</button>)}
    </div>
    <div role="tabpanel" id={`${prefix}-panel-0`} aria-labelledby={`${prefix}-tab-0`} hidden={active !== 0}>
    <section><h3>Start with a recording</h3>
      <ol>
        <li>Open Requests and choose an observed endpoint or the list of recordings that are not linked to an endpoint.</li>
        <li>Open a recording and select an event in Steps. Use the replay controls to move through the loaded events.</li>
        <li>Open Code, Values, Missing, or Details for the selected event and its available evidence.</li>
      </ol>
    </section>
    <section><h3>Words we use</h3>
      <dl>
        <dt>Step</dt><dd>An event in the recording. The sequence identifies the event in its recording.</dd>
        <dt>Call</dt><dd>An observed method or function entry. Map draws calls using observed frame relationships.</dd>
        <dt>Line</dt><dd>Code is highlighted only for a recorded line cursor with a matching source row.</dd>
        <dt>Value states</dt><dd>Captured values have a retained preview. {honesty.markers.redacted} {honesty.markers.truncated} {honesty.markers.unavailable} {honesty.markers.dropped}</dd>
        <dt>Inline values</dt><dd>Recorded local bindings displayed beside the selected line. Values also shows them when inline display is off.</dd>
        <dt>Focused capture</dt><dd>A capture mode that can provide more detailed evidence for selected Java application code. Check the recording for the evidence it contains.</dd>
        <dt>Not recorded</dt><dd>{honesty.markers.gap} The gap leaves execution unknown.</dd>
        <dt>Incomplete recording</dt><dd>{honesty.markers.incomplete} See Missing for the available reports.</dd>
        <dt>Source file changed</dt><dd>{honesty.markers.mismatch}</dd>
        <dt>Map</dt><dd>A view of recorded frames and their observed relationships. Position and size do not encode elapsed time.</dd>
      </dl>
    </section>
    </div>
    <div role="tabpanel" id={`${prefix}-panel-1`} aria-labelledby={`${prefix}-tab-1`} hidden={active !== 1}>
    <section><h3>Keyboard</h3>
      <dl>
        <dt><kbd>Alt + ↓ / ↑</kbd></dt><dd>Next or previous loaded event.</dd>
        <dt><kbd>Alt + Shift + ↓ / ↑</kbd></dt><dd>Next or previous call when its navigation target is loaded.</dd>
        <dt><kbd>Alt + I / O / U</kbd></dt><dd>Step in, over, or out when a target is available.</dd>
        <dt><kbd>Alt + M</kbd></dt><dd>Switch between Steps and Map.</dd>
        <dt><kbd>Alt + P</kbd></dt><dd>Replay or pause the selected recording. Esc also pauses outside text fields and dialogs.</dd>
        <dt><kbd>Alt + , / .</kbd></dt><dd>Slower or faster replay: 0.5×, 1×, 2× or 4×. Recorded timestamps stay unchanged.</dd>
        <dt><kbd>← / →</kbd> on viewer, recording, or Inspector tabs</dt><dd>Change the active tab.</dd>
        <dt><kbd>↑ / ↓</kbd> in Steps</dt><dd>Move between loaded events or browse adjacent loaded rows.</dd>
        <dt><kbd>Home / End</kbd> on a divider</dt><dd>Use the smallest or largest panel size. Enter collapses or restores it.</dd>
        <dt><kbd>Esc</kbd> in Settings or Help</dt><dd>Close the dialog and return focus to its button.</dd>
      </dl>
      <p>Replay shortcuts leave text fields and open dialogs available for editing and navigation.</p>
    </section>
    </div>
    <div role="tabpanel" id={`${prefix}-panel-2`} aria-labelledby={`${prefix}-tab-2`} hidden={active !== 2}>
    <section><h3>Layout</h3>
      <p>At narrow widths, use the viewer tabs to switch panes. The desktop Inspector can dock below Steps and Code or to their right. Use Reset panels to restore default panel sizes.</p>
    </section>
    </div>
  </>;
}
