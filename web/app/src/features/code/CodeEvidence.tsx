import { recordedLine, sourceRows } from '../../replay/source-rows';
import { sourceStateText } from '../../replay/source-states';
import type { ReplayEvent } from '../../types';
import { BindingList } from '../evidence/Values';
import './code-evidence.css';

export function CodeEvidence({ event }: { event: ReplayEvent }) {
  const source = event.source;
  const rows = sourceRows(event);
  const line = recordedLine(event);
  const localBindings = (event.bindings ?? []).filter((binding) => binding.role === 'local');

  return <>
    {source ? <p className="inspector-value">{source.path.split('/').at(-1)} · debug range L{source.startLine}
      {source.endLine && source.endLine !== source.startLine ? `–L${source.endLine}` : ''}</p> : null}
    <p className="evidence-state">{sourceStateText(event.sourceBinding, source)}</p>
    {source?.truncated ? <p className="evidence-state">Source excerpt is bounded</p> : null}
    {line !== null && !rows.some((row) => row.active) ? <p className="evidence-state">Recorded line cursor L{line}. No matching source row is available.</p> : null}
    {source?.status === 'matched' && rows.length === 0 ? <p className="evidence-state">No source excerpt is available for this event.</p> : null}
    {rows.length ? <ol role="list" className="source-excerpt source-rows" aria-label="Matched source excerpt">
      {rows.map((row) => <li className="source-row" key={row.number} data-source-line={row.number}
        aria-current={row.active ? 'location' : undefined}>
        <span className="source-number"><span className="sr-only">Line </span>{row.number}</span>
        <code className="source-text">{row.text}</code>
        {row.active && localBindings.length ? <div className="source-inline">
          <p>Local bindings at the recorded line cursor</p>
          <BindingList bindings={localBindings} inline />
        </div> : null}
      </li>)}
    </ol> : null}
  </>;
}
