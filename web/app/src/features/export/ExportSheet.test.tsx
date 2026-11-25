import { act, cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { ExportSheet } from './ExportSheet';
import type { ExportPreview, ExportSelection } from './client';

const id = 'abbccdde-0000-4000-8000-bbccddeeff00';
const catalogId = 'abbccdde-2222-4000-8000-bbccddeeff22';
const observedScope = 'observed:' + id;
const revision = 'abbccdde-1111-4000-8000-bbccddeeff11';
const digest = 'a'.repeat(64);
const endpoint = { operationId: id, method: 'POST', routeTemplate: '/orders' } as const;
function metadata(request: ExportSelection): ExportPreview {
  return { schemaVersion: 1, requestId: revision, projectId: id, request, revisionId: revision,
    catalogOperationId: request.scope === 'all' ? null : catalogId, revisionOrdinal: 7, selectedOperations: 1, emittedOperations: 1,
    files: [{ name: 'openapi.yaml', recipeOrdinal: null, mode: 420, bytes: 3, blake3: digest }],
    omissions: [{ format: 'openapi', kind: 'examples', reason: 'no_body_example', count: 1 }],
    totalBytes: 3, contentHash: digest, approval: { digest, revisionId: revision },
    download: { filename: 'openapi.yaml', mediaType: 'application/yaml' } };
}

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('previews the selected endpoint and saves only after explicit review', async () => {
  const user = userEvent.setup();
  const choice = { format: 'openapi', yaml: true, revision: 'latest', scope: observedScope } as const;
  const preview = metadata(choice);
  const fetch = vi.fn().mockResolvedValueOnce(Response.json(preview)).mockResolvedValueOnce(
    new Response('abc', { headers: { 'Content-Type': 'application/yaml', 'Content-Disposition': 'attachment; filename="openapi.yaml"' } }));
  vi.stubGlobal('fetch', fetch);
  const create = vi.fn(() => 'blob:local-test');
  vi.stubGlobal('URL', class extends URL { static createObjectURL = create; static revokeObjectURL = vi.fn(); });
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  render(<ExportSheet endpoint={endpoint} onClose={() => {}} />);
  expect(fetch).not.toHaveBeenCalled();
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  expect(await screen.findByRole('heading', { name: 'What’s left out' })).toBeVisible();
  expect(screen.getByText(/no body example/)).toBeVisible();
  expect(fetch.mock.calls[0]).toEqual(['/api/v1/exports/preview', expect.objectContaining({
    method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-XTrace-Client': 'viewer-v1' },
    body: JSON.stringify(choice),
  })]);
  expect(screen.getByText(/xtrace export --preview/)).toHaveTextContent('--operations ' + catalogId);
  await user.click(screen.getByRole('button', { name: 'Copy terminal command' }));
  expect(await navigator.clipboard.readText()).toContain('--operations ' + catalogId);
  expect(click).not.toHaveBeenCalled();
  await user.click(screen.getByRole('button', { name: 'Save file' }));
  expect(await screen.findByRole('heading', { name: 'Download started' })).toBeVisible();
  expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({ ...choice, approval: preview.approval });
  expect(create).toHaveBeenCalledOnce();
  expect(click).toHaveBeenCalledOnce();
});

it('requires a fresh preview before saving changed observations on the same revision', async () => {
  const user = userEvent.setup();
  const choice = { format: 'openapi', yaml: true, revision: 'latest', scope: 'all' } as const;
  const original = metadata(choice);
  const fresh = { ...original, approval: { revisionId: revision, digest: 'b'.repeat(64) } };
  const fetch = vi.fn().mockResolvedValueOnce(Response.json(original)).mockResolvedValueOnce(
    Response.json({ code: 'XTR-EXPORT-STALE', detail: 'private-value' }, { status: 409 }))
    .mockResolvedValueOnce(Response.json(fresh));
  vi.stubGlobal('fetch', fetch);
  render(<ExportSheet endpoint={null} onClose={() => {}} />);
  expect(screen.getByRole('button', { name: 'This endpoint' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  await user.click(await screen.findByRole('button', { name: 'Save file' }));
  expect(await screen.findByText(/linked observations changed/)).toBeVisible();
  expect(screen.queryByText(/private-value/)).toBeNull();
  expect(screen.queryByRole('button', { name: 'Save file' })).toBeNull();
  await user.click(screen.getByRole('button', { name: 'Refresh preview' }));
  expect(await screen.findByRole('button', { name: 'Save file' })).toBeEnabled();
  expect(fetch.mock.calls.map(([path]) => path)).toEqual(['/api/v1/exports/preview', '/api/v1/exports/save', '/api/v1/exports/preview']);
});

it('aborts an outstanding file request when the dialog closes', async () => {
  const user = userEvent.setup();
  const preview = metadata({ format: 'openapi', yaml: true, revision: 'latest', scope: observedScope });
  let finish!: (response: Response) => void;
  const fetch = vi.fn().mockResolvedValueOnce(Response.json(preview)).mockReturnValueOnce(new Promise<Response>((resolve) => { finish = resolve; }));
  vi.stubGlobal('fetch', fetch);
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  const view = render(<ExportSheet endpoint={endpoint} onClose={() => {}} />);
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  await user.click(await screen.findByRole('button', { name: 'Save file' }));
  const signal: AbortSignal = fetch.mock.calls[1][1].signal;
  view.unmount();
  expect(signal.aborted).toBe(true);
  await act(async () => {
    finish(new Response('abc', { headers: { 'Content-Type': 'application/yaml', 'Content-Disposition': 'attachment; filename="openapi.yaml"' } }));
  });
  expect(click).not.toHaveBeenCalled();
});
