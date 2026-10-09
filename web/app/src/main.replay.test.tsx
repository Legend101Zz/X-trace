/// <reference types="vite/client" />
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './main';

const operationA = '018f0000-0000-7000-8000-000000000001';
const recordingA = '018f0000-0000-7000-8000-000000000011';

const endpoints = { items: [{ operationId: operationA, projectId: 'p', applicationComponent: 'svc', binding: 'default', method: 'POST', routeTemplate: '/orders', observation: 'observed', observationPolicy: 'pol' }], nextCursor: null };
const linked = { items: [{ recordingId: recordingA, status: 'complete', completion: 'complete', openedAt: '2026-10-03T10:00:00Z', segmentCount: '1', eventCount: '4', firstSequence: '1', lastSequence: '4', incompleteEvidence: [], operationId: operationA, observationPolicy: 'pol', unmatchedReason: null }], nextCursor: null };

const none = { state: 'boundary' };
const nav = (over: Record<string, unknown>) => ({ previous: none, next: none, into: none, over: none, out: none, ...over });
const ev = (n: number, parent: string | null, symbol: string, navigation: object) => ({ sequence: String(n), frameId: `f${n}`, eventId: `event-${n}`, navigation, monotonicNs: String(n * 10), kind: 'method', symbol, parentFrameId: parent, sourceBinding: 'unspecified', fieldTruncations: [] });

const events = [
  ev(1, null, 'Controller.create', nav({ next: { state: 'target', frameId: 'f2' }, into: { state: 'target', frameId: 'f2' } })),
  ev(2, 'f1', 'Repo.save', nav({ previous: { state: 'target', frameId: 'f1' }, next: { state: 'target', frameId: 'f3' }, out: { state: 'target', frameId: 'f1' } })),
  ev(3, 'f1', 'Audit.log', nav({ previous: { state: 'target', frameId: 'f2' }, next: { state: 'target', frameId: 'f9-outside' }, out: { state: 'target', frameId: 'f1' } })),
  ev(4, 'f3', 'Audit.write', nav({ previous: { state: 'target', frameId: 'f3' } })),
];

const detail = {
  recordingId: recordingA, status: 'complete', completion: 'complete', adapterSummary: null, durationNs: '20', dropCountsByPriority: {}, segmentCount: '1', incompleteEvidence: [], nextCursor: null,
  unavailable: { source: 'unavailable', values: 'unavailable', completion: 'unavailable' },
  outcome: { kind: 'exception', httpStatus: 500, exception: { exceptionType: 'java.lang.IllegalStateException', message: 'boom' }, thrownFromEventId: null },
  events,
};

const json = (body: unknown) => Promise.resolve(new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } }));
const route = (input: RequestInfo | URL) => new URL(String(input), window.location.origin).pathname + new URL(String(input), window.location.origin).search;

async function openRecording() {
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: /POST \/orders/ }));
  fireEvent.click(await screen.findByRole('button', { name: new RegExp(recordingA) }));
  await screen.findByText('Controller.create');
  fireEvent.click(screen.getByRole('tab', { name: 'events' }));
}

const inspector = () => screen.getByRole('tabpanel', { name: 'evidence', hidden: true });

describe('replay wiring in the app', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/viewer#token=t');
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = route(input);
      if (path === '/api/v1/auth/exchange') return json({ authenticated: true });
      if (path.startsWith('/api/v1/endpoints?')) return json(endpoints);
      if (path.includes('/recordings') && path.includes('/endpoints/')) return json(linked);
      if (path.startsWith('/api/v1/recordings/')) return json(detail);
      throw new Error(`Unexpected request ${path}`);
    }));
  });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

  it('renders the outcome banner from the real outcome shape', async () => {
    await openRecording();
    const banner = screen.getByRole('region', { name: 'Recording outcome' });
    expect(within(banner).getByText('Response status 500 (as reported by the adapter)')).toBeInTheDocument();
    expect(within(banner).getByText('Exception java.lang.IllegalStateException: boom')).toBeInTheDocument();
  });

  it('keeps one selection across Linear -> Canvas -> inspector -> Linear', async () => {
    await openRecording();
    // Linear click selects event 2 (Repo.save).
    fireEvent.click(screen.getByRole('button', { name: /Repo\.save/ }));
    expect(within(inspector()).getByText('event-2')).toBeInTheDocument();
    // Switch to Canvas: the same frame is the selected tree item.
    fireEvent.click(screen.getByRole('button', { name: 'Canvas' }));
    const selected = () => screen.getAllByRole('treeitem').filter((item) => item.getAttribute('aria-selected') === 'true');
    expect(selected()).toHaveLength(1);
    expect(selected()[0]).toHaveTextContent('Repo.save');
    // Canvas click on another node drives the inspector.
    fireEvent.click(screen.getByRole('treeitem', { name: /Audit\.log/ }));
    expect(within(inspector()).getByText('event-3')).toBeInTheDocument();
    // Canvas arrow keys move in call order and keep the inspector in step.
    fireEvent.keyDown(screen.getByRole('tree'), { key: 'ArrowDown' });
    expect(within(inspector()).getByText('event-4')).toBeInTheDocument();
    // Back to Linear keeps that selection.
    fireEvent.click(screen.getByRole('button', { name: 'Linear' }));
    expect(screen.getByRole('button', { name: /Audit\.write/ })).toHaveAttribute('aria-current', 'true');
  });

  it('navigation buttons select the server-resolved target frame', async () => {
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: /Controller\.create/ }));
    fireEvent.click(within(inspector()).getByRole('button', { name: 'Step into' }));
    expect(within(inspector()).getByText('event-2')).toBeInTheDocument();
    fireEvent.click(within(inspector()).getByRole('button', { name: 'Step out' }));
    expect(within(inspector()).getByText('event-1')).toBeInTheDocument();
  });

  it('says why a target outside the loaded window cannot be reached, in the inspector and the live region', async () => {
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: /Audit\.log/ }));
    expect(within(inspector()).getByRole('button', { name: 'Next frame' })).toBeDisabled();
    expect(within(inspector()).getByText(/outside the loaded window/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Canvas' }));
    fireEvent.keyDown(screen.getByRole('tree'), { key: 'ArrowRight' });
    await waitFor(() => expect(screen.getByRole('status', { hidden: true })).toBeDefined());
  });
});
