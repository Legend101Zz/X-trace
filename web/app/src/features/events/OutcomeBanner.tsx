import { outcomeBanner } from '../../replay/outcome';
import type { Detail } from '../../types';

export function OutcomeBanner({ detail }: { detail: Detail }) {
  const outcome = detail.outcome;
  const model = outcomeBanner({ completion: detail.completion, incompleteEvidence: detail.incompleteEvidence, sessionContext: detail.sessionContext, durationNs: detail.durationNs, outcome });
  return <details open className="recording-why"><summary>Why?</summary><section className={`outcome-banner outcome-banner--${model.tone}`} aria-label="Recording outcome">
    <strong>{model.headline}</strong>
    <ul>{model.lines.map((line) => <li key={line}>{line}</li>)}</ul>
    {detail.limitations?.length ? <ul aria-label="Recorded capture limitations">{detail.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul> : null}
  </section></details>;
}
