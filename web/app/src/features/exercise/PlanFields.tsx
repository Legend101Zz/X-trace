import { useRef, useState } from 'react';
import type { Draft, InputValue, PlanBody, PlanInput } from './client';

export function PlanFields({ draft, onChange }: { draft: Draft; onChange: (next: Draft) => void }) {
  const nextKey = useRef(draft.inputs.length);
  const [keys, setKeys] = useState(() => draft.inputs.map((_, i) => i));
  function changeInput(i: number, next: PlanInput) {
    onChange({ ...draft, inputs: draft.inputs.map((old, j) => j === i ? next : old) });
  }
  return <>
    <fieldset><legend>Catalog selection</legend>
      <p>In your project, use <code>xtrace catalog list --json</code> to choose the revision and operation version. The recording does not identify its historical version.</p>
      <label>Catalog revision ID<input required value={draft.revision_id} onChange={e => onChange({ ...draft, revision_id: e.target.value })} /></label>
      <label>Operation version ID<input required maxLength={128} value={draft.selected_operation_version_id}
        onChange={e => onChange({ ...draft, selected_operation_version_id: e.target.value })} /></label>
    </fieldset>
    <fieldset><legend>Local development target</legend>
      <label>Loopback HTTP origin with port<input required type="text" inputMode="url" maxLength={128} value={draft.target.base_url}
        onChange={e => onChange({ ...draft, target: { base_url: e.target.value, operator_owned_development: false } })} /></label>
      <label className="plan-check"><input required type="checkbox" checked={draft.target.operator_owned_development}
        onChange={e => onChange({ ...draft, target: { ...draft.target, operator_owned_development: e.target.checked } })} />
        I own this local development application.</label>
      <label>Plan lifetime in seconds<input type="number" required min={1} max={900} value={draft.lifetime_seconds || ''}
        onChange={e => onChange({ ...draft, lifetime_seconds: Number(e.target.value) })} /></label>
    </fieldset>
    <fieldset><legend>Request body</legend><p>The body was not recorded. Choose what this plan should use.</p>
      <label>Body source<select value={draft.body.source} onChange={e => {
        const source = e.target.value as PlanBody['source'];
        onChange({ ...draft, body: source === 'operator' ? { source, content_type: 'application/json', content: '' } : { source } });
      }}><option value="not_recorded">Missing · not recorded</option><option value="empty_by_operator">I choose an empty body</option>
        <option value="operator">I will supply the body</option></select></label>
      {draft.body.source === 'operator' && <>
        <label>Content type<select value={draft.body.content_type} onChange={e => {
          if (draft.body.source === 'operator') onChange({ ...draft, body: { ...draft.body, content_type: e.target.value } });
        }}><option>application/json</option><option>text/plain</option></select></label>
        <label>Private body<textarea required maxLength={65536} rows={4} value={draft.body.content}
          onChange={e => { if (draft.body.source === 'operator') onChange({ ...draft, body: { ...draft.body, content: e.target.value } }); }} /></label>
      </>}
    </fieldset>
    <fieldset><legend>Request inputs</legend><p>For credentials, enter only an opaque reference name.</p>
      {draft.inputs.map((input, i) => <fieldset key={keys[i]}><legend>Input {i + 1}</legend>
        <label>Name<input required maxLength={128} value={input.name} onChange={e => changeInput(i, { ...input, name: e.target.value })} /></label>
        <label>Location<select value={input.location} onChange={e => {
          const location = e.target.value as PlanInput['location'];
          changeInput(i, { ...input, location, required: location === 'path' || input.required, value: { source: 'unresolved' } });
        }}>{['path','query','header','cookie'].map(loc => <option key={loc}>{loc}</option>)}</select></label>
        <label className="plan-check"><input type="checkbox" checked={input.required} disabled={input.location === 'path'}
          onChange={e => changeInput(i, { ...input, required: e.target.checked })} />Required</label>
        <label>Source<select value={input.value.source} onChange={e => {
          const source = e.target.value as InputValue['source'];
          changeInput(i, { ...input, value: source === 'credential_reference' ? { source, reference: '' } :
            source === 'operator' ? { source, value: '' } : { source } });
        }}><option value="unresolved">Missing</option>{input.location !== 'cookie' && <option value="operator">I will supply a value</option>}
          <option value="credential_reference">Credential reference</option></select></label>
        {input.value.source === 'operator' && <label>Private value<input maxLength={4096} value={input.value.value}
          onChange={e => changeInput(i, { ...input, value: { source: 'operator', value: e.target.value } })} /></label>}
        {input.value.source === 'credential_reference' && <label>Reference name<input required maxLength={64} value={input.value.reference}
          onChange={e => changeInput(i, { ...input, value: { source: 'credential_reference', reference: e.target.value } })} /></label>}
        <button type="button" className="button" onClick={() => {
          setKeys(keys.filter((_, j) => j !== i)); onChange({ ...draft, inputs: draft.inputs.filter((_, j) => j !== i) });
        }}>Remove input {i + 1}</button>
      </fieldset>)}
      {draft.inputs.length < 64 && <button type="button" className="button" onClick={() => {
        setKeys([...keys, nextKey.current++]); onChange({ ...draft, inputs: [...draft.inputs,
          { name: '', location: 'query', required: false, value: { source: 'unresolved' } }] });
      }}>Add input</button>}
    </fieldset>
  </>;
}
