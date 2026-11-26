import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { PlanSheet } from './PlanSheet';
import { planRequest } from './client';
import type { Binding, Draft, Review } from './client';

const binding: Binding = { project: 'project-a', recording: 'recording-a', operation: 'operation-a', method: 'POST', route: '/orders' };
const original = 'a'.repeat(64);
const replacement = 'b'.repeat(64);
const revision = 'ebea77b4-433e-42ba-a940-5cadbada22e5';
const version = 'version-a';
const target = 'http://127.0.0.1:6421';
const draft: Draft = { revision_id: revision, selected_operation_version_id: version, operation_id: binding.operation,
  recording_id: binding.recording, lifetime_seconds: 600, target: { base_url: target, operator_owned_development: true },
  inputs: [], body: { source: 'empty_by_operator' } };

function review(hash: string, phase: Review['phase']['phase']): Review {
  const now = Math.floor(Date.now() / 1000);
  const item = hash === original ? 'item-a' : 'item-b';
  return { kind: 'exercise_plan_review', project_id: binding.project, plan_id: 'plan-' + item, plan_hash: hash,
    observed_recording: { recording_id: binding.recording, operation_id: binding.operation, version_evidence: 'not_observed' },
    selected_catalog_operation: { operation_id: binding.operation, catalog: { revision_id: revision, operation_version_id: version, method: 'POST', route_template: '/orders' } },
    target: draft.target, inputs: [], body: draft.body, created_at: now, expires_at: now + 600, expired: false,
    ready_for_approval: phase === 'reviewed', phase: phase === 'approved' ? { phase, item_ids: [item] } : { phase },
    preview: { plan_hash: hash, items: [{ item_id: item, operation_id: binding.operation, request: 'POST /orders',
      selected: true, needs_approval: true, ready: true, effect: 'mutating' }] },
    requests_sent: 0, execution_available: false, ...(hash === replacement && { supersedes: original }) };
}
function response(doc: Review) { return new Response(JSON.stringify(doc), { status: 200 }); }
function sheet(lastHash = '', remember = vi.fn()) {
  return render(<PlanSheet binding={binding} lastHash={lastHash} remember={remember} onWrite={() => undefined} />);
}
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('creates, explicitly reviews, consents and replaces using only the local plan endpoints', async () => {
  const api = vi.fn()
    .mockResolvedValueOnce(response(review(original, 'draft')))
    .mockResolvedValueOnce(response(review(original, 'reviewed')))
    .mockResolvedValueOnce(response(review(original, 'approved')))
    .mockResolvedValueOnce(response(review(replacement, 'draft')))
    .mockResolvedValueOnce(response(review(replacement, 'reviewed')));
  vi.stubGlobal('fetch', api);
  sheet();
  expect(api).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Catalog revision ID'), { target: { value: revision.toUpperCase() } });
  fireEvent.change(screen.getByLabelText('Operation version ID'), { target: { value: version } });
  fireEvent.change(screen.getByLabelText('Loopback HTTP origin with port'), { target: { value: target } });
  fireEvent.click(screen.getByLabelText('I own this local development application.'));
  fireEvent.change(screen.getByLabelText('Body source'), { target: { value: 'empty_by_operator' } });
  expect(api).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Create private plan' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Mark this plan reviewed' }));
  const approve = await screen.findByRole('button', { name: 'Save item approval' });
  expect(approve).toBeDisabled();
  fireEvent.click(screen.getByLabelText(/^I approve POST/));
  expect(approve).toBeDisabled();
  fireEvent.click(screen.getByLabelText(/^I confirm that/));
  fireEvent.click(approve);
  await screen.findByText('Approval saved for this item. Sending is unavailable.');
  fireEvent.click(screen.getByRole('button', { name: 'Edit plan' }));
  fireEvent.change(screen.getByLabelText('Catalog revision ID'), { target: { value: revision.toUpperCase() } });
  fireEvent.click(screen.getByRole('button', { name: 'Save replacement plan' }));
  await screen.findByText('Replaced plan · prior approval revoked');
  expect(screen.queryByRole('button', { name: 'Save item approval' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Mark this plan reviewed' }));
  expect(await screen.findByRole('button', { name: 'Save item approval' })).toBeDisabled();
  const prefix = '/api/v1/exercise/plans';
  expect(api.mock.calls.map(([url]) => url)).toEqual([
    prefix, prefix + '/' + original + '/review', prefix + '/' + original + '/approve',
    prefix + '/' + original + '/edit', prefix + '/' + replacement + '/review',
  ]);
  expect(JSON.parse(api.mock.calls[0][1].body)).toEqual(draft);
  expect(JSON.parse(api.mock.calls[3][1].body)).toEqual(draft);
  expect(JSON.parse(api.mock.calls[2][1].body)).toEqual({ plan_id: 'plan-item-a', item_ids: ['item-a'], confirm_owned_development: true });
  for (const [, options] of api.mock.calls) {
    expect(options).toMatchObject({ method: 'POST', cache: 'no-store', credentials: 'same-origin', mode: 'same-origin', redirect: 'error' });
  }
});

it('restores a closed plan only on explicit read and displays the server expiry', async () => {
  const api = vi.fn().mockResolvedValue(response({ ...review(original, 'reviewed'), expired: true, ready_for_approval: false }));
  vi.stubGlobal('fetch', api);
  sheet(original);
  expect(api).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Show saved plan' }));
  expect(await screen.findByText('The plan has expired.')).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Save item approval' })).toBeNull();
  expect(api.mock.calls[0][1]).toMatchObject({ method: 'GET', cache: 'no-store' });
  expect(api.mock.calls[0][1]).not.toHaveProperty('body');
});

it('refuses a returned item from a different observed recording before showing private values', async () => {
  const doc = review(original, 'reviewed');
  doc.observed_recording.recording_id = 'another-recording';
  doc.body = { source: 'operator', content_type: 'text/plain', content: 'example body content' };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(doc)));
  sheet(original);
  fireEvent.click(screen.getByRole('button', { name: 'Show saved plan' }));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('could not verify'));
  expect(screen.queryByText('example body content')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Save item approval' })).toBeNull();
});

it('refuses malformed hashes without issuing any viewer request', async () => {
  const api = vi.fn();
  vi.stubGlobal('fetch', api);
  await expect(planRequest(binding, { action: 'show', previous: 'invalid' }, new AbortController().signal)).rejects.toThrow('plan hash');
  expect(api).not.toHaveBeenCalled();
});

it('rejects a malformed catalog revision before create or replacement can write', async () => {
  const api = vi.fn();
  vi.stubGlobal('fetch', api);
  const invalid = { ...draft, revision_id: 'bad-revision' };
  for (const op of [{ action: 'create', draft: invalid }, { action: 'edit', previous: original, draft: invalid }] as const) {
    await expect(planRequest(binding, op, new AbortController().signal)).rejects.toThrow('hyphenated UUID');
  }
  expect(api).not.toHaveBeenCalled();
});

it('describes a missing create receipt without retrying or assuming a new hash', async () => {
  const api = vi.fn().mockRejectedValue(new Error('lost response'));
  vi.stubGlobal('fetch', api);
  await expect(planRequest(binding, { action: 'create', draft }, new AbortController().signal))
    .rejects.toThrow('Without a confirmed hash this viewer cannot find it');
  expect(api).toHaveBeenCalledTimes(1);
});
