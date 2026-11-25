import type { Binding } from '../../replay/value-evidence';
import { valueEvidence } from '../../replay/value-evidence';
import './values.css';

export function BindingList({ bindings, inline = false }: { bindings: readonly Binding[]; inline?: boolean }) {
  return <ul className={`value-list${inline ? ' inline-values' : ''}`}>
    {bindings.map((binding, index) => {
      const item = valueEvidence(binding);
      return <li key={index} className="value-binding" data-value-state={item.state}>
        <div className="value-name">
          <span className="mono">{binding.name || 'Name unavailable'}</span>
          <span className="value-state">{item.label}</span>
        </div>
        {!inline ? <p className="value-metadata">{binding.role || 'Role unavailable'} · {binding.nameOrigin || 'Name origin unavailable'}</p> : null}
        {typeof item.preview === 'string' ? <code className="value-preview">{item.preview === '' ? 'Empty preview' : item.preview}</code> : null}
        {item.wording ? <details className="value-why">
          <summary>Why?</summary>
          <p>{item.wording}</p>
          {item.reason ? <p>{item.reason}</p> : null}
        </details> : null}
      </li>;
    })}
  </ul>;
}

export function Values({ bindings }: { bindings: readonly Binding[] }) {
  return <section className="inspector-section" aria-label="Values">
    <h2 className="inspector-label">Values ({bindings.length})</h2>
    {bindings.length ? <BindingList bindings={bindings} /> : <p className="evidence-state">No value bindings were recorded for this event</p>}
  </section>;
}
