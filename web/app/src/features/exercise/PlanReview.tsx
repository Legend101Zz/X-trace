import type { Review } from './client';

export function PlanReview({ doc }: { doc: Review }) {
  const item = doc.preview.items[0];
  const catalog = doc.selected_catalog_operation.catalog;
  return <div className="plan-review">
    <h3>{item.request}</h3>
    <dl>
      <dt>Target</dt><dd>{doc.target.base_url}</dd>
      <dt>Effect</dt><dd>{{ mutating: 'May change data', read_only: 'Read-only candidate · the effect on the application is unverified', unknown: 'Unknown effect' }[item.effect]}</dd>
      <dt>Saved phase</dt><dd>{doc.phase.phase}</dd>
      <dt>Plan ID</dt><dd><code>{doc.plan_id}</code></dd>
      <dt>Plan hash</dt><dd><code>{doc.plan_hash}</code></dd>
      {doc.supersedes && <><dt>Replaced plan · prior approval revoked</dt><dd><code>{doc.supersedes}</code></dd></>}
      <dt>Expires</dt><dd><time>{new Date(doc.expires_at * 1000).toLocaleString()}</time></dd>
      <dt>Recording</dt><dd>{doc.observed_recording.recording_id}</dd>
      <dt>Observed operation</dt><dd>{doc.observed_recording.operation_id}</dd>
      <dt>Selected catalog revision</dt><dd>{catalog.revision_id}</dd>
      <dt>Selected operation version</dt><dd>{catalog.operation_version_id}</dd>
      <dt>Request body</dt><dd>{doc.body.source === 'operator'
        ? <><span>Supplied by you · {doc.body.content_type}</span><pre>{doc.body.content}</pre></>
        : doc.body.source === 'empty_by_operator' ? 'Empty by your choice' : 'Missing · not recorded'}</dd>
      <dt>Inputs</dt><dd>{doc.inputs.length === 0 ? 'No inputs declared' : <ul>{doc.inputs.map(p =>
        <li key={p.location + ':' + p.name}><b>{p.location} · {p.name}</b> {p.required ? '(required)' : '(optional)'} · {p.value.source === 'credential_reference'
          ? 'Credential reference: ' + p.value.reference : p.value.source === 'operator' ? 'Supplied by you: ' + p.value.value : 'Missing'}</li>)}</ul>}</dd>
      <dt>Item ID</dt><dd><code>{item.item_id}</code></dd>
    </dl>
    {doc.phase.phase === 'approved' && <p>Approval saved for this item. Sending is unavailable.</p>}
    {doc.phase.phase === 'consumed' && <p>Reserved. Delivery is unknown.</p>}
  </div>;
}
