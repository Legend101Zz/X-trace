/** The private plan API has no command that can execute an exercise. */
export type Binding = { project: string; recording: string; operation: string; method: string; route: string };
export type InputValue = { source: 'unresolved' } | { source: 'operator'; value: string } |
  { source: 'credential_reference'; reference: string };
export type PlanInput = { name: string; location: 'path' | 'query' | 'header' | 'cookie'; required: boolean; value: InputValue };
export type PlanBody = { source: 'not_recorded' } | { source: 'empty_by_operator' } |
  { source: 'operator'; content_type: string; content: string };
export type Draft = {
  revision_id: string; operation_id: string; selected_operation_version_id: string; recording_id: string;
  target: { base_url: string; operator_owned_development: boolean };
  inputs: PlanInput[]; body: PlanBody; lifetime_seconds: number;
};
type Item = { item_id: string; operation_id: string; request: string; selected: boolean;
  effect: 'read_only' | 'mutating' | 'unknown'; needs_approval: boolean; ready: boolean };
export type Review = {
  kind: 'exercise_plan_review'; project_id: string; plan_hash: string; plan_id: string;
  observed_recording: { recording_id: string; operation_id: string; version_evidence: 'not_observed' };
  selected_catalog_operation: { operation_id: string; catalog: { revision_id: string; operation_version_id: string; method: string; route_template: string } };
  target: Draft['target']; inputs: PlanInput[]; body: PlanBody;
  created_at: number; expires_at: number; expired: boolean; ready_for_approval: boolean;
  phase: { phase: 'draft' | 'reviewed' | 'approved' | 'superseded' | 'consumed'; item_ids?: string[]; replacement_hash?: string };
  preview: { plan_hash: string; items: Item[] }; supersedes?: string; requests_sent: number; execution_available: boolean;
};

const hash = /^[0-9a-f]{64}$/;
function canonicalRevision(value: string) {
  const revision = value.trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(revision)) {
    throw new Error('Enter the catalog revision as a hyphenated UUID.');
  }
  return revision;
}

const phases = ['draft', 'reviewed', 'approved', 'superseded', 'consumed'];
const errors: Record<string, string> = {
  'XTR-EXERCISE-INPUT': 'Check the target, catalog identifiers, body and inputs.',
  'XTR-EXERCISE-CREDENTIAL': 'Remove literal credentials. Use a credential reference for a credential input.',
  'XTR-EXERCISE-BINDING': 'The selected revision, operation version and recording could not be linked.',
  'XTR-EXERCISE-UNRESOLVED': 'Supply the missing inputs and choose a request body.',
  'XTR-EXERCISE-EXPIRED': 'This plan has expired.',
  'XTR-EXERCISE-SUPERSEDED': 'This plan has been replaced. Refresh its status to find its successor.',
  'XTR-EXERCISE-CONFLICT': 'The plan changed. Refresh its status before continuing.',
  'XTR-EXERCISE-CONSUMED': 'This plan was already reserved. Refresh its status.',
  'XTR-EXERCISE-STAGING': 'Private plan storage requires operator attention.',
  'XTR-EXERCISE-APPROVAL': 'Review the exact plan and confirm the target and item.',
};
type Operation = { action: 'create'; draft: Draft } | { action: 'edit'; previous: string; draft: Draft } |
  { action: 'review' | 'show'; previous: string } | { action: 'approve'; previous: string; planId: string; item: string };

function validBody(body: PlanBody) {
  return body?.source === 'not_recorded' || body?.source === 'empty_by_operator' ||
    (body?.source === 'operator' && typeof body.content === 'string' && ['text/plain', 'application/json'].includes(body.content_type));
}
function validInput(input: PlanInput) {
  const value = input?.value;
  return typeof input?.name === 'string' && ['path','query','header','cookie'].includes(input.location) &&
    typeof input.required === 'boolean' && (value?.source === 'unresolved' ||
    (value?.source === 'operator' && typeof value.value === 'string') ||
    (value?.source === 'credential_reference' && typeof value.reference === 'string'));
}

export const missingCreateReceipt = 'A draft may have been saved. Without a confirmed hash this viewer cannot find it. Creating again can make a second draft.';
export class UnconfirmedPlanResult extends Error {}

export async function planRequest(binding: Binding, op: Operation, signal: AbortSignal): Promise<Review> {
  let path = '/api/v1/exercise/plans';
  if ('previous' in op) {
    if (!hash.test(op.previous)) throw new Error('Enter the complete 64-character plan hash.');
    path += '/' + op.previous;
    if (op.action !== 'show') path += '/' + op.action;
  }
  const revision = 'draft' in op ? canonicalRevision(op.draft.revision_id) : undefined;
  const payload = 'draft' in op ? { ...op.draft, revision_id: revision } : op.action === 'approve'
    ? { plan_id: op.planId, item_ids: [op.item], confirm_owned_development: true } : {};
  const read = op.action === 'show';
  const unconfirmed = op.action === 'create'
    ? missingCreateReceipt
    : op.action === 'show' ? 'The viewer could not read the saved plan.' : 'Refresh the original plan to check its saved state before repeating this action.';
  const result = await fetch(path, {
    method: read ? 'GET' : 'POST', cache: 'no-store', mode: 'same-origin', credentials: 'same-origin',
    redirect: 'error', referrerPolicy: 'same-origin', signal, headers: {
      'X-XTrace-Client': 'viewer-v1', ...(!read && { 'Content-Type': 'application/json' }),
    }, ...(!read && { body: JSON.stringify(payload) }),
  }).catch(() => { throw new UnconfirmedPlanResult(unconfirmed); });
  if (!result.ok) {
    const problem = await result.json().catch(() => null);
    if (typeof problem?.code === 'string' && Object.hasOwn(errors, problem.code)) throw new Error(errors[problem.code]);
    if (result.status === 401) throw new Error('The viewer session expired.');
    throw new UnconfirmedPlanResult(unconfirmed);
  }
  const doc: Review = await result.json().catch(() => null);
  const item = doc?.preview?.items?.[0];
  const catalog = doc?.selected_catalog_operation?.catalog;
  if (doc?.kind !== 'exercise_plan_review' || !hash.test(doc.plan_hash) || !doc.plan_id ||
      doc.project_id !== binding.project || doc.observed_recording?.recording_id !== binding.recording ||
      doc.observed_recording.operation_id !== binding.operation || doc.observed_recording.version_evidence !== 'not_observed' ||
      doc.selected_catalog_operation?.operation_id !== binding.operation || !catalog?.revision_id || !catalog.operation_version_id ||
      typeof catalog.method !== 'string' || typeof catalog.route_template !== 'string' ||
      !phases.includes(doc.phase?.phase) || doc.preview?.plan_hash !== doc.plan_hash ||
      !Array.isArray(doc.preview.items) || doc.preview.items.length !== 1 || !item?.item_id || item.operation_id !== binding.operation ||
      item.selected !== true || item.needs_approval !== true || !['read_only','mutating','unknown'].includes(item.effect) ||
      typeof item.request !== 'string' || doc.target?.operator_owned_development !== true || typeof doc.target.base_url !== 'string' ||
      !Array.isArray(doc.inputs) || !doc.inputs.every(validInput) || !validBody(doc.body) ||
      !Number.isSafeInteger(doc.created_at) || !Number.isSafeInteger(doc.expires_at) || doc.expires_at <= doc.created_at ||
      doc.requests_sent !== 0 || doc.execution_available !== false || typeof doc.expired !== 'boolean' ||
      typeof doc.ready_for_approval !== 'boolean' ||
      ('draft' in op && (catalog.revision_id !== revision || catalog.operation_version_id !== op.draft.selected_operation_version_id ||
        doc.target.base_url !== op.draft.target.base_url || doc.expires_at - doc.created_at !== op.draft.lifetime_seconds)) ||
      (op.action === 'create' && (doc.phase.phase !== 'draft' || doc.supersedes !== undefined)) ||
      (op.action === 'edit' && (doc.supersedes !== op.previous || doc.plan_hash === op.previous || doc.phase.phase !== 'draft')) ||
      ('previous' in op && op.action !== 'edit' && doc.plan_hash !== op.previous) ||
      (op.action === 'review' && !['reviewed','approved'].includes(doc.phase.phase)) ||
      (doc.phase.phase === 'superseded' && !hash.test(doc.phase.replacement_hash ?? '')) ||
      (doc.phase.phase === 'approved' && (doc.phase.item_ids?.length !== 1 || doc.phase.item_ids[0] !== item.item_id)) ||
      (op.action === 'approve' && (doc.phase.phase !== 'approved' || doc.plan_id !== op.planId || item.item_id !== op.item))) {
    throw new UnconfirmedPlanResult('The viewer could not verify the returned plan identity or state. ' + unconfirmed);
  }
  return doc;
}

export function editDraft(doc: Review): Draft {
  const { catalog } = doc.selected_catalog_operation;
  return { revision_id: catalog.revision_id, selected_operation_version_id: catalog.operation_version_id,
    operation_id: doc.observed_recording.operation_id, recording_id: doc.observed_recording.recording_id,
    target: doc.target, inputs: doc.inputs, body: doc.body, lifetime_seconds: doc.expires_at - doc.created_at };
}
