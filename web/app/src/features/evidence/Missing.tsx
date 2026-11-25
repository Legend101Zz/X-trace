import type { MissingEntry, MissingTarget } from '../../replay/missing';
import { WhyDisclosure } from './WhyDisclosure';

function MissingList({ entries, onGoTo }: { entries: MissingEntry[]; onGoTo: (target: MissingTarget) => void }) {
  return <ul className="missing-list">
    {entries.map(({ key, label, detail, explanation, target }) => <li key={key} className="missing-entry">
      <strong>{label}</strong>
      <p>{detail}{target ? ` · event sequence ${target.sequence}` : ''}</p>
      <WhyDisclosure lines={explanation} label={label} />
      {target ? <button className="button" type="button" onClick={() => onGoTo(target)}>Go to event {target.sequence}</button>
        : <p className="evidence-state">No loaded event target</p>}
    </li>)}
  </ul>;
}

export function Missing({ window, recording, session, onGoTo }: {
  window: MissingEntry[];
  recording: MissingEntry[];
  session: string | null;
  onGoTo: (target: MissingTarget) => void;
}) {
  return <>
    <section aria-label="Loaded window missing evidence">
      <h2>Loaded window ({window.length})</h2>
      {window.length ? <MissingList entries={window} onGoTo={onGoTo} />
        : <p className="evidence-state">No missing evidence entries in the loaded window.</p>}
    </section>
    <section aria-label="Recording reports">
      <h2>Recording reports ({recording.length})</h2>
      {recording.length ? <MissingList entries={recording} onGoTo={onGoTo} /> : <p className="evidence-state">No recording reports in this response.</p>}
    </section>
    <section aria-label="Session report">
      <h2>Session report</h2>
      <p>{session ?? 'Session context unavailable'}</p>
    </section>
  </>;
}
