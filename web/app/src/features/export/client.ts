import type { components } from '../../api.generated';

export type ExportSelection = components['schemas']['ExportSelection'];
export type ExportPreview = components['schemas']['ExportPreview'];
type Download = components['schemas']['ExportDownload'];

const messages: Record<string, string> = {
  'XTR-EXPORT-EVIDENCE': 'The catalog evidence is incomplete. A complete export preview is unavailable.',
  'XTR-EXPORT-UNAVAILABLE': 'The local catalog is temporarily unavailable. Try again.',
  'XTR-EXPORT-INVALID': 'The local viewer could not use this export selection.',
  'XTR-EXPORT-NO-CATALOG': 'This project has no published catalog to export.',
  'XTR-EXPORT-REVISION': 'This catalog revision is unavailable. Choose a current revision.',
  'XTR-EXPORT-OPERATION': 'This endpoint is absent from the selected catalog revision. You can preview all eligible endpoints.',
  'XTR-EXPORT-STALE': 'The catalog or linked observations changed. Refresh the preview to review the current export.',
  'XTR-EXPORT-SANITIZER': 'The exporter found content it could not safely include.',
  'XTR-EXPORT-LIMIT': 'This export exceeds the viewer limit. Try a single endpoint.',
};

export class ExportProblem extends Error {
  constructor(readonly code: string, status: number) {
    super(messages[code] ?? ({
      401: 'The viewer session expired. Open a new local viewer link.',
      403: 'The local viewer refused this request.',
      413: 'This export exceeds the viewer limit. Try a single endpoint.',
      503: 'The viewer is busy. Try again.',
      504: 'The export took too long. Try a single endpoint.',
    } as Record<number, string>)[status] ?? 'The local viewer could not complete this export.');
  }
}

async function post(action: 'preview' | 'save', body: ExportSelection | components['schemas']['ExportSaveRequest'], signal: AbortSignal) {
  const response = await fetch('/api/v1/exports/' + action, {
    method: 'POST',
    mode: 'same-origin',
    credentials: 'same-origin',
    redirect: 'error',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json', 'X-XTrace-Client': 'viewer-v1' },
    body: JSON.stringify(body),
    signal,
  });
  if (!response.ok) {
    const problem = await response.json().catch(() => null);
    throw new ExportProblem(typeof problem?.code === 'string' ? problem.code : '', response.status);
  }
  return response;
}

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function matchesOperation(scope: string, operationId: string | null) {
  if (scope === 'all') return operationId === null;
  if (operationId === null || !uuid.test(operationId)) return false;
  if (scope.startsWith('observed:')) return uuid.test(scope.slice('observed:'.length));
  return scope === operationId;
}

function attachment(selection: ExportSelection): Download {
  switch (selection.format) {
    case 'openapi': return selection.yaml
      ? { filename: 'openapi.yaml', mediaType: 'application/yaml' }
      : { filename: 'openapi.json', mediaType: 'application/json' };
    case 'postman': return { filename: 'collection.postman.json', mediaType: 'application/json' };
    case 'curl': return { filename: 'xtrace-curl.zip', mediaType: 'application/zip' };
    case 'bundle': return { filename: 'xtrace-bundle.zip', mediaType: 'application/zip' };
  }
}

export async function previewExport(selection: ExportSelection, signal: AbortSignal): Promise<ExportPreview> {
  const response = await post('preview', selection, signal);
  const preview: ExportPreview = await response.json();
  const expected = attachment(selection);
  if (!uuid.test(preview.revisionId) || !matchesOperation(selection.scope, preview.catalogOperationId) ||
      preview.schemaVersion !== 1 || preview.request.format !== selection.format ||
      preview.request.yaml !== selection.yaml || preview.request.scope !== selection.scope ||
      preview.request.revision !== selection.revision || preview.revisionId !== preview.approval.revisionId ||
      preview.download.filename !== expected.filename || preview.download.mediaType !== expected.mediaType) {
    throw new ExportProblem('', 500);
  }
  return preview;
}

export async function fetchExportFile(preview: ExportPreview, signal: AbortSignal): Promise<Blob> {
  const response = await post('save', { ...preview.request, approval: preview.approval }, signal);
  const expected = attachment(preview.request);
  if (response.headers.get('Content-Type')?.split(';')[0] !== expected.mediaType ||
      response.headers.get('Content-Disposition') !== `attachment; filename="${expected.filename}"`) {
    throw new ExportProblem('', 500);
  }
  return response.blob();
}

export function startDownload(file: Blob, name: Download['filename']) {
  const url = URL.createObjectURL(file);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.append(link);
  try {
    link.click();
  } finally {
    link.remove();
    // Give the browser time to consume the download before releasing its local buffer.
    window.setTimeout(URL.revokeObjectURL.bind(URL, url), 30_000);
  }
}
