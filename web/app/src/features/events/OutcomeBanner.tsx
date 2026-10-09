import { outcomeBanner } from '../../replay/outcome';
import type { OutcomeView } from '../../replay/outcome';
import type { Detail } from '../../types';

export function OutcomeBanner({ detail }: { detail: Detail }) {
  const outcome = (detail as Detail & { outcome?: OutcomeView | null }).outcome;
  const model = outcomeBanner({ completion: detail.completion, incompleteEvidence: detail.incompleteEvidence, durationNs: detail.durationNs, outcome });
  return <section className={`outcome-banner outcome-banner--${model.tone}`} aria-label="Recording outcome">
    <strong>{model.headline}</strong>
    <ul>{model.lines.map((line) => <li key={line}>{line}</li>)}</ul>
  </section>;
}
