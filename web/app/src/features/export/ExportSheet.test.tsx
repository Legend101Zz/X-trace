import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { ExportSheet } from './ExportSheet';
import type { ExportPreview, ExportSelection } from './client';

const id = 'abbccdde-0000-4000-8000-bbccddeeff00';
// The registered /orders alias shares its UUID; selector kinds remain distinct.
const catalogId = id;
const observedScope = 'observed:' + id;
const revision = 'abbccdde-1111-4000-8000-bbccddeeff11';
const digest = 'a'.repeat(64);
const endpoint = { operationId: id, method: 'POST', routeTemplate: '/orders' } as const;
function metadata(request: ExportSelection): ExportPreview {
  const download: ExportPreview['download'] = request.format === 'openapi'
    ? { filename: request.yaml ? 'openapi.yaml' : 'openapi.json', mediaType: request.yaml ? 'application/yaml' : 'application/json' }
    : request.format === 'postman' ? { filename: 'collection.postman.json', mediaType: 'application/json' }
      : { filename: request.format === 'curl' ? 'xtrace-curl.zip' : 'xtrace-bundle.zip', mediaType: 'application/zip' };
  const logicalName = request.format === 'curl' ? 'all.sh' : request.format === 'bundle' ? 'manifest.json' : download.filename;
  return { schemaVersion: 1, requestId: revision, projectId: id, request, revisionId: revision,
    catalogOperationId: request.scope === 'all' ? null : catalogId, revisionOrdinal: 7, selectedOperations: 1, emittedOperations: 1,
    files: [{ name: logicalName, recipeOrdinal: null, mode: 420, bytes: 3, blake3: digest }],
    omissions: [{ format: 'openapi', kind: 'examples', reason: 'no_body_example', count: 1 }],
    totalBytes: 3, contentHash: digest, approval: { digest, revisionId: revision },
    download };
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
  expect(screen.getByText('Files will be saved on this machine only. Nothing will be sent anywhere.')).toBeVisible();
  expect(fetch.mock.calls[0]).toEqual(['/api/v1/exports/preview', expect.objectContaining({
    method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-XTrace-Client': 'viewer-v1' },
    body: JSON.stringify(choice),
  })]);
  expect(screen.getByText(/xtrace export --preview/)).toHaveTextContent('--operations ' + catalogId);
  const previewCommand = `xtrace export --preview --revision ${revision} --format openapi --operations ${catalogId} --yaml`;
  expect(screen.getByLabelText('Terminal command')).toHaveTextContent(previewCommand);
  expect(screen.getByLabelText('Terminal command')).not.toHaveTextContent('--output');
  await user.click(screen.getByRole('button', { name: 'Copy terminal command' }));
  expect(await navigator.clipboard.readText()).toContain('--operations ' + catalogId);
  expect(await navigator.clipboard.readText()).toBe(previewCommand);
  expect(await navigator.clipboard.readText()).not.toContain(observedScope);
  expect(click).not.toHaveBeenCalled();
  await user.click(screen.getByRole('button', { name: 'Save file' }));
  expect(await screen.findByRole('heading', { name: 'Download started' })).toBeVisible();
  expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({ ...choice, approval: preview.approval });
  expect(create).toHaveBeenCalledOnce();
  expect(click).toHaveBeenCalledOnce();
  const writeCommand = `xtrace export --output ./xtrace-export --revision ${revision} --format openapi --operations ${catalogId} --yaml`;
  expect(screen.getByLabelText('Terminal command')).toHaveTextContent(writeCommand);
  expect(screen.getByLabelText('Terminal command')).not.toHaveTextContent('--preview');
  expect(screen.getByText(/empty directory owned by you with private permissions/)).toBeVisible();
  expect(screen.getByText(/Linked observations may have changed/)).toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Copy terminal command' }));
  expect(await navigator.clipboard.readText()).toBe(writeCommand);
  expect(screen.getByRole('status')).toHaveTextContent('Terminal export command copied.');
});

it.each([
  { format: 'openapi', label: 'OpenAPI 3.1', yaml: true },
  { format: 'openapi', label: 'OpenAPI 3.1', yaml: false },
  { format: 'postman', label: 'Postman Collection 2.1', yaml: false },
  { format: 'curl', label: 'cURL recipes', yaml: false },
  { format: 'bundle', label: 'Developer bundle', yaml: false },
] as const)('keeps $format / YAML $yaml and all-endpoint scope in both terminal phases', async ({ format, label, yaml }) => {
  const user = userEvent.setup();
  const choice = { format, yaml, revision: 'latest', scope: 'all' } as const;
  const preview = metadata(choice);
  const fetch = vi.fn().mockResolvedValueOnce(Response.json(preview)).mockResolvedValueOnce(new Response('abc', {
    headers: { 'Content-Type': preview.download.mediaType, 'Content-Disposition': `attachment; filename="${preview.download.filename}"` },
  }));
  vi.stubGlobal('fetch', fetch);
  vi.stubGlobal('URL', class extends URL { static createObjectURL = vi.fn(() => 'blob:local-test'); static revokeObjectURL = vi.fn(); });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  render(<ExportSheet endpoint={null} onClose={() => {}} />);
  await user.click(screen.getByRole('button', { name: new RegExp(label) }));
  if (format === 'openapi' && !yaml) await user.selectOptions(screen.getByRole('combobox', { name: 'File type' }), 'json');
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  await screen.findByRole('heading', { name: 'What’s left out' });
  const tail = `--revision ${revision} --format ${format}${yaml ? ' --yaml' : ''}`;
  expect(screen.getByLabelText('Terminal command')).toHaveTextContent(`xtrace export --preview ${tail}`);
  expect(screen.getByLabelText('Terminal command')).not.toHaveTextContent('--operations');
  await user.click(screen.getByRole('button', { name: 'Save file' }));
  await screen.findByRole('heading', { name: 'Download started' });
  await user.click(screen.getByRole('button', { name: 'Copy terminal command' }));
  expect(await navigator.clipboard.readText()).toBe(`xtrace export --output ./xtrace-export ${tail}`);
  expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({ ...choice, approval: preview.approval });
});

it('selects metadata with the keyboard, pages the inventory and discloses exact omission reasons', async () => {
  const user = userEvent.setup();
  const preview = metadata({ format: 'bundle', yaml: false, revision: 'latest', scope: 'all' });
  preview.files.push(...Array.from({ length: 17 }, (_, index) => ({
    name: null, recipeOrdinal: index + 1, mode: 420 as const, bytes: index + 4, blake3: (index + 1).toString(16).padStart(64, '0'),
  })));
  preview.selectedOperations = 17;
  preview.emittedOperations = 17;
  preview.totalBytes = preview.files.reduce((bytes, file) => bytes + file.bytes, 0);
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(preview)));
  render(<ExportSheet endpoint={null} onClose={() => {}} />);
  await user.click(screen.getByRole('button', { name: /Developer bundle/ }));
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  const first = await screen.findByRole('tab', { name: 'manifest.json' });
  expect(first).toHaveAttribute('aria-selected', 'true');
  expect(screen.getByRole('tabpanel', { name: 'manifest.json' })).toHaveTextContent('3 bytes');
  first.focus();
  await user.keyboard('{ArrowDown}');
  const recipe = screen.getByRole('tab', { name: 'Recipe 1 (filename withheld)' });
  expect(recipe).toHaveFocus();
  expect(recipe).toHaveAttribute('aria-selected', 'true');
  expect(screen.getByRole('tabpanel', { name: 'Recipe 1 (filename withheld)' })).toHaveTextContent('4 bytes');
  expect(screen.getByLabelText('File BLAKE3')).toHaveTextContent('1'.padStart(64, '0'));
  await user.keyboard('{End}');
  expect(screen.getByRole('tab', { name: 'Recipe 15 (filename withheld)' })).toHaveFocus();
  await user.keyboard('{Home}');
  expect(first).toHaveFocus();
  await user.keyboard('{ArrowUp}');
  expect(screen.getByRole('tab', { name: 'Recipe 15 (filename withheld)' })).toHaveFocus();
  await user.click(screen.getByRole('button', { name: 'Next files' }));
  expect(screen.getAllByRole('tab')).toHaveLength(2);
  expect(screen.getByRole('tab', { name: 'Recipe 16 (filename withheld)' })).toHaveAttribute('aria-selected', 'true');
  expect(screen.getByRole('tabpanel', { name: 'Recipe 16 (filename withheld)' })).toHaveTextContent('19 bytes');
  await user.click(screen.getByRole('button', { name: 'Previous files' }));
  expect(screen.getByRole('tab', { name: 'manifest.json' })).toHaveAttribute('aria-selected', 'true');
  const why = screen.getByText('Why?');
  expect(why.parentElement).not.toHaveAttribute('open');
  await user.click(why);
  expect(why.parentElement).toHaveAttribute('open');
  expect(within(why.parentElement!).getByText('no_body_example')).toBeVisible();
  expect(screen.getByText(/File contents are not included in this preview/)).toBeVisible();
});

it('keeps the displayed command available when clipboard permission is unavailable', async () => {
  const user = userEvent.setup();
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(metadata({ format: 'openapi', yaml: true, revision: 'latest', scope: 'all' }))));
  vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValueOnce(new Error('unavailable'));
  render(<ExportSheet endpoint={null} onClose={() => {}} />);
  await user.click(screen.getByRole('button', { name: 'Preview' }));
  await user.click(await screen.findByRole('button', { name: 'Copy terminal command' }));
  expect(screen.getByRole('status')).toHaveTextContent('Select and copy the displayed command.');
  expect(screen.getByLabelText('Terminal command')).toHaveTextContent('--preview');
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

it('reveals the whole focused action only when the dialog body is the short-layout scroller', () => {
  render(<div className="viewer-dialog-body" data-testid="body"><ExportSheet endpoint={endpoint} onClose={() => {}} /></div>);
  const body = screen.getByTestId('body');
  const action = screen.getByRole('button', { name: 'Preview' });
  const scrollBy = vi.fn();
  Object.defineProperties(body, { clientHeight: { value: 200 }, scrollBy: { value: scrollBy } });
  vi.spyOn(body, 'getBoundingClientRect').mockReturnValue(new DOMRect(16, 54, 704, 200));
  const bounds = vi.spyOn(action, 'getBoundingClientRect').mockReturnValue(new DOMRect(600, 224, 85, 44));
  body.style.overflowY = 'hidden';
  fireEvent.focus(action);
  expect(scrollBy).not.toHaveBeenCalled();
  body.style.overflowY = 'auto';
  fireEvent.focus(action);
  expect(scrollBy).toHaveBeenLastCalledWith({ top: 18, behavior: 'instant' });
  bounds.mockReturnValue(new DOMRect(600, 48, 85, 44));
  fireEvent.focus(action);
  expect(scrollBy).toHaveBeenLastCalledWith({ top: -10, behavior: 'instant' });
  bounds.mockReturnValue(new DOMRect(600, 110, 85, 44));
  fireEvent.focus(action);
  expect(scrollBy).toHaveBeenCalledTimes(2);
});
