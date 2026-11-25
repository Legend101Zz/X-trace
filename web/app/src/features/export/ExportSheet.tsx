import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
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

function terminalCommand(preview: ExportPreview, write: boolean) {
  const { format, yaml } = preview.request;
  const args = ['xtrace', 'export', ...(write ? ['--output', './xtrace-export'] : ['--preview']), '--revision', preview.revisionId, '--format', format];
  if (preview.catalogOperationId) args.push('--operations', preview.catalogOperationId);
  if (yaml) args.push('--yaml');
  return args.join(' ');
}

function fileLabel(file: ExportPreview['files'][number]) {
  return file.name ?? `Recipe ${file.recipeOrdinal} (filename withheld)`;
}

function FileInventory({ preview, children }: { preview: ExportPreview; children: ReactNode }) {
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState(0);
  const buttons = useRef<(HTMLButtonElement | null)[]>([]);
  const id = useId();
  const size = 16;
  const files = preview.files.slice(page * size, (page + 1) * size);
  const file = preview.files[selected];
  function changePage(next: number) {
    setPage(next);
    setSelected(next * size);
  }
  return <div className="export-preview"><section aria-label="Files in this export">
    <h3>Files ({preview.files.length})</h3>
    <div className="export-files" role="tablist" aria-label="Export files" aria-orientation="vertical">{files.map((entry, offset) => {
      const index = page * size + offset;
      return <button type="button" role="tab" key={entry.name ?? entry.recipeOrdinal}
        ref={(element) => { buttons.current[index] = element; }} id={`${id}-file-${index}`} aria-controls={`${id}-metadata`}
        aria-selected={selected === index} tabIndex={selected === index ? 0 : -1} onClick={() => setSelected(index)}
        onKeyDown={(event) => {
          const next = event.key === 'ArrowDown' ? (offset + 1) % files.length :
            event.key === 'ArrowUp' ? (offset + files.length - 1) % files.length :
              event.key === 'Home' ? 0 : event.key === 'End' ? files.length - 1 : null;
          if (next === null) return;
          event.preventDefault();
          const nextIndex = page * size + next;
          setSelected(nextIndex);
          buttons.current[nextIndex]?.focus();
        }}>{fileLabel(entry)}</button>;
    })}</div>
    {preview.files.length > size && <nav className="export-actions" aria-label="File inventory pages">
      <button type="button" disabled={page === 0} onClick={() => changePage(page - 1)}>Previous files</button>
      <span>Page {page + 1} of {Math.ceil(preview.files.length / size)}</span>
      <button type="button" disabled={(page + 1) * size >= preview.files.length} onClick={() => changePage(page + 1)}>Next files</button>
    </nav>}
    {children}
  </section><section className="export-file-preview" aria-label="File metadata preview">
    <h3>{file ? <>Preview of {fileLabel(file)} · metadata only</> : 'File metadata'}</h3>
    {file ? <div role="tabpanel" id={`${id}-metadata`} aria-labelledby={`${id}-file-${selected}`} tabIndex={0}>
      <dl className="export-file-facts">
        <div><dt>Size</dt><dd>{file.bytes.toLocaleString()} bytes</dd></div>
        <div><dt>Logical mode</dt><dd>{file.mode.toString(8).padStart(4, '0')}</dd></div>
        <div><dt>File BLAKE3</dt><dd><code aria-label="File BLAKE3">{file.blake3}</code></dd></div>
      </dl>
    </div> : <p>The exporter reported no logical files.</p>}
    <p>File contents are not included in this preview. The size, logical mode and digest describe the exported file.</p>
  </section></div>;
}

function PreviewDetails({ preview }: { preview: ExportPreview }) {
  return <FileInventory preview={preview}>
      <h3>Included</h3>
      <p>{preview.selectedOperations} selected · {preview.emittedOperations} emitted</p>
      <p>{preview.totalBytes.toLocaleString()} bytes across the logical files</p>
      <p>Catalog revision {preview.revisionOrdinal} <code>{preview.revisionId}</code></p>
      <h3>What’s left out</h3>
      <p>Captured request and response bodies, cookies and credentials stay out of the export.</p>
      {preview.omissions.length ? <ul className="export-omissions">{preview.omissions.map((group) =>
        <li key={[group.format, group.kind, group.reason].join('/')}>
          <p>{group.count} × {group.kind.replaceAll('_', ' ')}{group.format && ` (${group.format})`} · {group.reason.replaceAll('_', ' ')}</p>
          <details><summary>Why?</summary><dl>
            <div><dt>Exporter reason</dt><dd><code>{group.reason}</code></dd></div>
            <div><dt>Subject</dt><dd>{group.kind}</dd></div>
            <div><dt>Applies to</dt><dd>{group.format ?? 'Whole export'}</dd></div>
            <div><dt>Omission entries</dt><dd>{group.count}</dd></div>
          </dl></details>
        </li>)}</ul> : <p>The exporter reported no additional omissions.</p>}
      <p>Logical content BLAKE3 <code>{preview.contentHash}</code></p>
  </FileInventory>;
}

export type ExportPhase = 'Choose' | 'Preview' | 'Save';

export function ExportProgress({ phase }: { phase: ExportPhase }) {
  return <nav aria-label="Export progress"><ol className="export-progress">{(['Choose', 'Preview', 'Save'] as const).map((label, index) =>
    <li key={label} aria-current={phase === label ? 'step' : undefined}><span>{index + 1}</span>{label}</li>)}</ol></nav>;
}

export function ExportSheet({ endpoint, onClose, onPhaseChange }: {
  endpoint: Pick<Endpoint, 'operationId' | 'method' | 'routeTemplate'> | null;
  onClose: () => void;
  onPhaseChange?: (phase: ExportPhase) => void;
}) {
  const [format, setFormat] = useState<ExportSelection['format']>('openapi');
  const [yaml, setYaml] = useState(true);
  const [oneEndpoint, setOneEndpoint] = useState(endpoint !== null);
  const [phase, setPhase] = useState<ExportPhase>('Choose');
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
    const panel = focusTarget.current;
    if (!panel) return;
    panel.scrollTop = 0;
    const body = panel.closest<HTMLElement>('.viewer-dialog-body');
    if (body) body.scrollTop = 0;
    if (phase !== 'Choose') panel.focus({ preventScroll: true });
  }, [phase]);
  useEffect(() => { onPhaseChange?.(phase); }, [phase, onPhaseChange]);

  function choose() {
    active.current?.abort();
    active.current = null;
    setBusy(false);
    setStale(false);
    setPreview(null);
    setFeedback('');
    setPhase('Choose');
    requestAnimationFrame(() => focusTarget.current?.focus({ preventScroll: true }));
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

  const terminal = preview && terminalCommand(preview, phase === 'Save');
  async function copyCommand() {
    if (!terminal) return;
    try {
      await navigator.clipboard.writeText(terminal);
      setFeedback(phase === 'Save' ? 'Terminal export command copied.' : 'Terminal preview command copied.');
    } catch {
      setFeedback('Clipboard access is unavailable. Select and copy the displayed command.');
    }
  }
  return <article className="export-sheet">
    {!onPhaseChange && <ExportProgress phase={phase} />}
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
      {phase !== 'Choose' && terminal && <div className="export-command"><h3>{phase === 'Save' ? 'The same export from a terminal' : 'Preview this revision in the terminal'}</h3>
        <p>Run from the initialized project root. Linked observations may have changed since this preview.</p>
        {phase === 'Save' ? <p>Use a fresh output directory, or an empty directory owned by you with private permissions (mode 0700).
          This example creates ./xtrace-export if absent; choose a fresh path if it already contains files. Its parent directory must exist.</p> :
          <p>This command previews metadata without writing files.</p>}
        <code aria-label="Terminal command">{terminal}</code></div>}
      {format === 'postman' && <p>Configure Postman workspace delivery in the terminal.</p>}
    </section>
    <div className="export-feedback" role="status">{busy ? phase === 'Choose' || stale ? 'Preparing preview…' : 'Preparing download…' : feedback}</div>
    <footer className="export-actions export-footer">
      {phase === 'Choose' && <><span>Nothing is saved yet. You always see a preview first.</span><button type="button" className="export-primary" disabled={busy}
        onClick={() => void submit('preview')}>Preview</button></>}
      {phase === 'Preview' && <><span>Files will be saved on this machine only. Nothing will be sent anywhere.</span><button type="button" onClick={choose}>Back</button>
        <button type="button" onClick={() => void copyCommand()}>Copy terminal command</button><button type="button" className="export-primary"
        disabled={busy} onClick={() => void submit(stale ? 'preview' : 'save')}>{stale ? 'Refresh preview' : 'Save file'}</button></>}
      {phase === 'Save' && <><button type="button" onClick={choose}>Export something else</button>
        <button type="button" onClick={() => void copyCommand()}>Copy terminal command</button>
        <button type="button" className="export-primary" onClick={onClose}>Done</button></>}
    </footer>
  </article>;
}
