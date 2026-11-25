import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import type { Endpoint } from '../../types';
import { ExportProblem, fetchExportFile, previewExport, startDownload } from './client';
import type { ExportPreview, ExportSelection } from './client';
import './export.css';

const formats = [
  ['openapi', 'OpenAPI 3.1', 'An API description of the selected catalog endpoints.'],
  ['postman', 'Postman Collection 2.1', 'Requests you can open in Postman.'],
  ['curl', 'cURL recipes', 'Shell scripts for the selected endpoints. Saving them runs no requests.'],
  ['bundle', 'Developer bundle', 'The API description, collection and recipes with their manifest.'],
] as const;

function terminalPreview(preview: ExportPreview) {
  const { format, yaml } = preview.request;
  const args = ['xtrace', 'export', '--preview', '--revision', preview.revisionId, '--format', format];
  if (preview.catalogOperationId) args.push('--operations', preview.catalogOperationId);
  if (yaml) args.push('--yaml');
  return args.join(' ');
}

function FileInventory({ preview }: { preview: ExportPreview }) {
  const [page, setPage] = useState(0);
  const size = 16;
  const files = preview.files.slice(page * size, (page + 1) * size);
  return <section aria-label="Files in this export">
    <h3>Files ({preview.files.length})</h3>
    <ul className="export-files">{files.map((file) => <li key={file.name ?? file.recipeOrdinal}>
      <strong>{file.name ?? `Recipe ${file.recipeOrdinal} (filename withheld)`}</strong>
      <span>{file.bytes.toLocaleString()} bytes · mode {file.mode.toString(8).padStart(4, '0')}</span>
      <code aria-label="File BLAKE3">{file.blake3}</code>
    </li>)}</ul>
    {preview.files.length > size && <nav className="export-actions" aria-label="File inventory pages">
      <button type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous files</button>
      <span>Page {page + 1} of {Math.ceil(preview.files.length / size)}</span>
      <button type="button" disabled={(page + 1) * size >= preview.files.length} onClick={() => setPage(page + 1)}>Next files</button>
    </nav>}
  </section>;
}

function PreviewDetails({ preview }: { preview: ExportPreview }) {
  return <div className="export-preview">
    <div>
      <h3>Included</h3>
      <p>{preview.selectedOperations} selected · {preview.emittedOperations} emitted</p>
      <p>{preview.totalBytes.toLocaleString()} bytes across the logical files</p>
      <p>Catalog revision {preview.revisionOrdinal} <code>{preview.revisionId}</code></p>
      <h3>What’s left out</h3>
      <p>Captured request and response bodies, cookies and credentials stay out of the export.</p>
      {preview.omissions.length ? <ul>{preview.omissions.map((group) =>
        <li key={[group.format, group.kind, group.reason].join('/')}>
          {group.count} × {group.kind.replaceAll('_', ' ')}{group.format && ` (${group.format})`} · {group.reason.replaceAll('_', ' ')}
        </li>)}</ul> : <p>The exporter reported no additional omissions.</p>}
      <p>Logical content BLAKE3 <code>{preview.contentHash}</code></p>
    </div>
    <FileInventory preview={preview} />
  </div>;
}

type Phase = 'Choose' | 'Preview' | 'Save';

export function ExportSheet({ endpoint, onClose }: { endpoint: Pick<Endpoint, 'operationId' | 'method' | 'routeTemplate'> | null; onClose: () => void }) {
  const [format, setFormat] = useState<ExportSelection['format']>('openapi');
  const [yaml, setYaml] = useState(true);
  const [oneEndpoint, setOneEndpoint] = useState(endpoint !== null);
  const [phase, setPhase] = useState<Phase>('Choose');
  const [preview, setPreview] = useState<ExportPreview | null>(null);
  const [stale, setStale] = useState(false);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState('');
  const active = useRef<AbortController | null>(null);
  const focusTarget = useRef<HTMLElement>(null);
  const formatId = useId();
  const scopeId = useId();

  // Unmounting the modal invalidates both in-flight responses and browser downloads.
  useLayoutEffect(() => () => { active.current?.abort(); }, []);
  useEffect(() => {
    if (phase !== 'Choose') focusTarget.current?.focus();
  }, [phase]);

  function choose() {
    active.current?.abort();
    active.current = null;
    setBusy(false);
    setStale(false);
    setPreview(null);
    setFeedback('');
    setPhase('Choose');
    requestAnimationFrame(() => focusTarget.current?.focus());
  }

  async function submit(action: 'preview' | 'save') {
    if (active.current || (action === 'save' && (!preview || stale))) return;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setFeedback('');
    try {
      if (action === 'save' && preview) {
        const file = await fetchExportFile(preview, controller.signal);
        if (controller.signal.aborted) return;
        startDownload(file, preview.download.filename);
        setPhase('Save');
      } else {
        const selection: ExportSelection = {
          format, yaml: format === 'openapi' && yaml, revision: 'latest',
          scope: oneEndpoint && endpoint ? 'observed:' + endpoint.operationId : 'all',
        };
        const result = await previewExport(selection, controller.signal);
        if (controller.signal.aborted) return;
        setPreview(result);
        setStale(false);
        setPhase('Preview');
      }
    } catch (error) {
      if (controller.signal.aborted) return;
      if (action === 'save') setStale(true);
      setFeedback(error instanceof ExportProblem ? error.message : 'The export could not be completed. Try again.');
    } finally {
      if (active.current === controller) {
        active.current = null;
        if (!controller.signal.aborted) setBusy(false);
      }
    }
  }

  const terminal = preview && terminalPreview(preview);
  async function copyCommand() {
    if (!terminal) return;
    try {
      await navigator.clipboard.writeText(terminal);
      setFeedback('Terminal preview command copied.');
    } catch {
      setFeedback('Clipboard access is unavailable. Select and copy the displayed command.');
    }
  }
  return <article className="export-sheet">
    <nav aria-label="Export progress"><ol className="export-progress">{(['Choose', 'Preview', 'Save'] as const).map((label, index) =>
      <li key={label} aria-current={phase === label ? 'step' : undefined}><span>{index + 1}</span>{label}</li>)}</ol></nav>
    <section ref={focusTarget} tabIndex={-1} aria-label={phase + ' export'} aria-busy={busy}>
      {phase === 'Choose' && <>
        <h3 id={formatId}>Format</h3>
        <div className="export-formats" role="group" aria-labelledby={formatId}>
          {formats.map(([value, label, description]) => <button key={value} type="button" disabled={busy}
            aria-pressed={format === value} onClick={() => setFormat(value)}>
            <strong>{label}</strong><span>{description}</span>
          </button>)}
        </div>
        {format === 'openapi' && <label className="export-encoding">File type <select disabled={busy} value={yaml ? 'yaml' : 'json'}
          onChange={(event) => setYaml(event.target.value === 'yaml')}><option value="yaml">YAML</option><option value="json">JSON</option></select></label>}
        <h3 id={scopeId}>What to export</h3>
        <div className="export-actions" role="group" aria-labelledby={scopeId}>
          <button type="button" disabled={!endpoint || busy} aria-pressed={oneEndpoint} onClick={() => setOneEndpoint(true)}>This endpoint</button>
          <button type="button" disabled={busy} aria-pressed={!oneEndpoint} onClick={() => setOneEndpoint(false)}>All eligible endpoints</button>
        </div>
        <p>{!endpoint ? 'This endpoint is unavailable because no linked catalog endpoint is selected.' :
          oneEndpoint ? `${endpoint.method} ${endpoint.routeTemplate}` : 'All eligible endpoints in the latest catalog revision.'}</p>
      </>}
      {phase === 'Preview' && preview && <PreviewDetails key={preview.approval.digest} preview={preview} />}
      {phase === 'Save' && preview && <><h3>Download started</h3><p>Check your browser’s downloads for <strong>{preview.download.filename}</strong>.</p>
        <p>Logical content BLAKE3 <code>{preview.contentHash}</code></p></>}
      {phase !== 'Choose' && terminal && <div className="export-command"><h3>Preview this revision in the terminal</h3><p>Run from the initialized project root. Linked observations may have changed since this preview.</p><code>{terminal}</code>
        <button type="button" onClick={() => void copyCommand()}>Copy terminal command</button></div>}
      {format === 'postman' && <p>Configure Postman workspace delivery in the terminal.</p>}
    </section>
    <div className="export-feedback" role="status">{busy ? phase === 'Choose' || stale ? 'Preparing preview…' : 'Preparing download…' : feedback}</div>
    <footer className="export-actions export-footer">
      {phase === 'Choose' && <><span>Preview the files before saving.</span><button type="button" className="export-primary" disabled={busy}
        onClick={() => void submit('preview')}>Preview</button></>}
      {phase === 'Preview' && <><button type="button" onClick={choose}>Back</button><button type="button" className="export-primary"
        disabled={busy} onClick={() => void submit(stale ? 'preview' : 'save')}>{stale ? 'Refresh preview' : 'Save file'}</button></>}
      {phase === 'Save' && <><button type="button" onClick={choose}>Export something else</button>
        <button type="button" className="export-primary" onClick={onClose}>Done</button></>}
    </footer>
  </article>;
}
