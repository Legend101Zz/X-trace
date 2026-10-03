/// <reference types="vite/client" />
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './main';
import { retainPage } from './retained-page';

const operationA = '018f0000-0000-7000-8000-000000000001';
const recordingA = '018f0000-0000-7000-8000-000000000011';
const recordingB = '018f0000-0000-7000-8000-000000000012';
const legacyV4 = '018f0000-0000-4000-8000-000000000013';

const endpoints = {
  items: [
    { operationId: operationA, projectId: 'project-1', applicationComponent: 'spring-fixture', binding: 'default', method: 'POST', routeTemplate: '/orders', observation: 'observed', observationPolicy: 'spring-orders-v1' },
  ], nextCursor: null,
};
const linked = {
  items: [
    { recordingId: recordingA, status: 'complete', openedAt: '2026-10-03T10:00:00Z', segmentCount: '1', eventCount: '1', firstSequence: '1', lastSequence: '1', incompleteEvidence: [], operationId: operationA, observationPolicy: 'spring-orders-v1', unmatchedReason: null },
  ], nextCursor: null,
};
const unmatched = {
  items: [
    { recordingId: recordingB, status: 'partial', openedAt: '2026-10-03T10:01:00Z', segmentCount: '1', eventCount: '1', firstSequence: '1', lastSequence: '1', incompleteEvidence: [], operationId: null, observationPolicy: 'spring-orders-v1', unmatchedReason: 'route_unapproved' },
    { recordingId: legacyV4, status: 'complete', openedAt: '2025-01-01T00:00:00Z', segmentCount: '1', eventCount: '1', firstSequence: '1', lastSequence: '1', incompleteEvidence: [], operationId: null, observationPolicy: null, unmatchedReason: null },
  ], nextCursor: null,
};

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function detail(recordingId: string, symbol = 'fixture.Service.call') {
  return {
    recordingId, status: 'complete', segmentCount: '1', incompleteEvidence: [], nextCursor: null,
    unavailable: { source: 'unavailable', values: 'unavailable', completion: 'unavailable' },
    events: [{ sequence: '1', monotonicNs: '10', kind: 'method', symbol, fieldTruncations: [] }],
  };
}

function route(input: RequestInfo | URL): string { return new URL(String(input), window.location.origin).pathname + new URL(String(input), window.location.origin).search; }

function defaultFetch(input: RequestInfo | URL) {
  const path = route(input);
  if (path === '/api/v1/auth/exchange') return Promise.resolve(response({ authenticated: true }));
  if (path.startsWith('/api/v1/endpoints?')) return Promise.resolve(response(endpoints));
  if (path.includes('/recordings?unmatched=true')) return Promise.resolve(response(unmatched));
  if (path.includes('/api/v1/endpoints/') && path.includes('/recordings')) return Promise.resolve(response(linked));
  if (path.startsWith('/api/v1/recordings/')) return Promise.resolve(response(detail(path.split('/')[4])));
  throw new Error(`Unexpected request ${path}`);
}

describe('endpoint-first recording viewer', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/viewer?keep=query#token=test-bootstrap');
    vi.stubGlobal('fetch', vi.fn(defaultFetch));
  });

  afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

  it('opens observed endpoints first, then only their linked recording and verified detail', async () => {
    render(<App />);
    expect(await screen.findByRole('button', { name: /POST \/orders Component: spring-fixture Binding: default observed/ })).toBeInTheDocument();
    expect(screen.getByText('Operator-selected policy')).toBeInTheDocument();
    expect(screen.getByText('spring-orders-v1 does not attest which adapter or application produced the event.')).toBeInTheDocument();
    expect(window.location.hash).toBe('');
    expect(window.location.search).toBe('?keep=query');

    const calls = vi.mocked(fetch).mock.calls.map(([input]) => route(input as RequestInfo | URL));
    expect(calls.some((url) => url.startsWith('/api/v1/recordings?'))).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: /POST \/orders Component: spring-fixture Binding: default observed/ }));
    expect(await screen.findByRole('button', { name: new RegExp(recordingA) })).toBeInTheDocument();
    expect(screen.queryByText(recordingB)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: new RegExp(recordingA) }));
    expect(await screen.findByText('fixture.Service.call')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('tab', { name: 'events' }));
    fireEvent.keyDown(window, { key: 'ArrowDown', altKey: true });
    expect(window.location.hash).toBe('');
    for (const [input, init] of vi.mocked(fetch).mock.calls) {
      const url = new URL(String(input), window.location.origin);
      expect(url.origin).toBe(window.location.origin);
      expect(url.hash).toBe('');
      if (url.pathname !== '/api/v1/auth/exchange') expect(JSON.stringify(init)).not.toContain('test-bootstrap');
    }
  });

  it('keeps unmatched separate and displays a legacy null reason without inventing one', async () => {
    render(<App />);
    await screen.findByText('Operator-selected policy');
    fireEvent.click(screen.getByRole('button', { name: 'Unmatched recordings' }));
    expect(await screen.findByRole('button', { name: new RegExp(recordingB) })).toBeInTheDocument();
    const legacyRow = screen.getByRole('button', { name: new RegExp(legacyV4) });
    expect(legacyRow).toHaveTextContent('No historical reason recorded');
    expect(legacyRow).not.toHaveTextContent('route_unapproved');
    fireEvent.click(legacyRow);
    expect(await screen.findByText('fixture.Service.call')).toBeInTheDocument();
    expect(vi.mocked(fetch).mock.calls.some(([input]) => route(input as RequestInfo | URL).includes(`/${legacyV4}?limit=200`))).toBe(true);
  });

  it('ignores an obsolete linked 401 and clears that lane after returning to endpoints', async () => {
    let resolveFirst: ((response: Response) => void) | undefined;
    vi.mocked(fetch).mockImplementation((input: RequestInfo | URL) => {
      const path = route(input);
      if (path === '/api/v1/auth/exchange') return Promise.resolve(response({ authenticated: true }));
      if (path.startsWith('/api/v1/endpoints?')) return Promise.resolve(response(endpoints));
      if (path.includes(`/endpoints/${operationA}/recordings`)) return new Promise((resolve) => { resolveFirst = resolve; });
      throw new Error(`Unexpected request ${path}`);
    });
    render(<App />);
    const endpointButtons = await screen.findAllByRole('button', { name: /POST \/orders Component: spring-fixture Binding: default observed/ });
    fireEvent.click(endpointButtons[0]);
    await waitFor(() => expect(resolveFirst).toBeDefined());
    fireEvent.click(screen.getByRole('button', { name: '← Observed endpoints' }));
    await act(async () => { resolveFirst?.(response({ detail: 'stale private route payload' }, 401)); });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByText('Viewer session expired')).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Endpoints' })).toBeInTheDocument();
  });

  it.each([
    { outcome: 'success', status: 200, body: { items: [unmatched.items[0]], nextCursor: null } },
    { outcome: '401', status: 401, body: { detail: 'stale session response' } },
  ])('ignores an obsolete unmatched $outcome after returning to endpoints', async ({ status, body }) => {
    let resolveUnmatched: ((response: Response) => void) | undefined;
    vi.mocked(fetch).mockImplementation((input: RequestInfo | URL) => {
      const path = route(input);
      if (path === '/api/v1/auth/exchange') return Promise.resolve(response({ authenticated: true }));
      if (path.startsWith('/api/v1/endpoints?')) return Promise.resolve(response(endpoints));
      if (path.includes('/recordings?unmatched=true')) return new Promise((resolve) => { resolveUnmatched = resolve; });
      if (path.startsWith('/api/v1/recordings/')) return Promise.resolve(response(detail(path.split('/')[4], 'stale-unmatched-selection')));
      throw new Error(`Unexpected request ${path}`);
    });
    render(<App />);
    await screen.findByRole('button', { name: /POST \/orders Component: spring-fixture Binding: default observed/ });
    fireEvent.click(screen.getByRole('button', { name: 'Unmatched recordings' }));
    await waitFor(() => expect(resolveUnmatched).toBeDefined());
    fireEvent.click(screen.getByRole('button', { name: 'Observed endpoints' }));
    await act(async () => { resolveUnmatched?.(response(body, status)); });
    expect(screen.getByRole('heading', { name: 'Endpoints' })).toBeInTheDocument();
    expect(screen.queryByText('Viewer session expired')).not.toBeInTheDocument();
    expect(screen.queryByText('stale-unmatched-selection')).not.toBeInTheDocument();
    expect(vi.mocked(fetch).mock.calls.some(([input]) => route(input as RequestInfo | URL).startsWith('/api/v1/recordings/'))).toBe(false);
  });

  it('ignores an endpoint error and busy state after switching into unmatched mode', async () => {
    let resolveOld: ((response: Response) => void) | undefined;
    let endpointRequests = 0;
    vi.mocked(fetch).mockImplementation((input: RequestInfo | URL) => {
      const path = route(input);
      if (path === '/api/v1/auth/exchange') return Promise.resolve(response({ authenticated: true }));
      if (path.startsWith('/api/v1/endpoints?')) {
        endpointRequests += 1;
        if (endpointRequests === 1) return Promise.resolve(response(endpoints));
        return new Promise((resolve) => { resolveOld = resolve; });
      }
      if (path.includes('/recordings?unmatched=true')) return Promise.resolve(response(unmatched));
      throw new Error(`Unexpected request ${path}`);
    });
    render(<App />);
    await screen.findByRole('button', { name: /POST \/orders Component: spring-fixture Binding: default observed/ });
    fireEvent.click(screen.getAllByRole('button', { name: 'Refresh' })[0]);
    await waitFor(() => expect(endpointRequests).toBe(2));
    fireEvent.click(screen.getByRole('button', { name: 'Unmatched recordings' }));
    expect(await screen.findByRole('button', { name: new RegExp(recordingB) })).toBeInTheDocument();
    await act(async () => { resolveOld?.(response({ detail: 'stale endpoint error' }, 422)); });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Unmatched recordings' })).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Refresh' })[0]).toBeEnabled();
  });

  it('uses safe status for pagination errors without rendering server detail or request ID', async () => {
    vi.mocked(fetch).mockImplementation((input: RequestInfo | URL) => {
      const path = route(input);
      if (path === '/api/v1/auth/exchange') return Promise.resolve(response({ authenticated: true }));
      if (path.startsWith('/api/v1/endpoints?')) return Promise.resolve(response(endpoints));
      if (path.includes('cursor=next-safe-cursor')) return Promise.resolve(response({ detail: 'UNTRUSTED_SERVER_CANARY', requestId: 'request-safe-1' }, 422));
      if (path.includes('/recordings?unmatched=true')) return Promise.resolve(response({ items: unmatched.items.slice(0, 1), nextCursor: 'next-safe-cursor' }));
      throw new Error(`Unexpected request ${path}`);
    });
    render(<App />);
    await screen.findByText('Operator-selected policy');
    fireEvent.click(screen.getByRole('button', { name: 'Unmatched recordings' }));
    await screen.findByRole('button', { name: new RegExp(recordingB) });
    fireEvent.click(screen.getByRole('button', { name: 'Load next page' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Request failed with status 422.');
    expect(screen.queryByText('request-safe-1')).not.toBeInTheDocument();
    expect(screen.queryByText('UNTRUSTED_SERVER_CANARY')).not.toBeInTheDocument();
  });

  it('removes a missing bootstrap fragment before showing the authentication error', async () => {
    window.history.replaceState(null, '', '/viewer#not-a-token');
    const fetchMock = vi.mocked(fetch);
    render(<App />);
    expect(await screen.findByRole('alert')).toHaveTextContent('The one-time viewer link is missing.');
    expect(window.location.hash).toBe('');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('keeps the newer recording detail when an older selection resolves late', async () => {
    let resolveFirst: ((response: Response) => void) | undefined;
    vi.mocked(fetch).mockImplementation((input: RequestInfo | URL) => {
      const path = route(input);
      if (path === '/api/v1/auth/exchange') return Promise.resolve(response({ authenticated: true }));
      if (path.startsWith('/api/v1/endpoints?')) return Promise.resolve(response(endpoints));
      if (path.includes('/endpoints/') && path.endsWith('/recordings?limit=50')) return Promise.resolve(response({ ...linked, items: [linked.items[0], { ...linked.items[0], recordingId: recordingB }] }));
      if (path.startsWith(`/api/v1/recordings/${recordingA}?`)) return new Promise((resolve) => { resolveFirst = resolve; });
      if (path.startsWith(`/api/v1/recordings/${recordingB}?`)) return Promise.resolve(response(detail(recordingB, 'newer-recording-detail')));
      throw new Error(`Unexpected request ${path}`);
    });
    render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: /POST \/orders Component: spring-fixture Binding: default observed/ }));
    fireEvent.click(await screen.findByRole('button', { name: new RegExp(recordingA) }));
    await waitFor(() => expect(resolveFirst).toBeDefined());
    fireEvent.click(screen.getByRole('button', { name: new RegExp(recordingB) }));
    expect(await screen.findByText('newer-recording-detail')).toBeInTheDocument();
    await act(async () => { resolveFirst?.(response(detail(recordingA, 'stale-recording-detail'))); });
    expect(screen.getByRole('heading', { name: recordingB })).toBeInTheDocument();
    expect(screen.queryByText('stale-recording-detail')).not.toBeInTheDocument();
  });

  it('expires the current viewer session after an authenticated endpoint request returns 401', async () => {
    vi.mocked(fetch).mockImplementation((input: RequestInfo | URL) => route(input) === '/api/v1/auth/exchange'
      ? Promise.resolve(response({ authenticated: true }))
      : Promise.resolve(response({ detail: 'sensitive server wording' }, 401)));
    render(<App />);
    expect(await screen.findByText('Viewer session expired')).toBeInTheDocument();
    expect(screen.queryByText('sensitive server wording')).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'recordings' })).toBeInTheDocument();
  });

  it('keeps event stepping, truncation, unavailable evidence, and recording-scoped cursors', async () => {
    const firstEvents = [
      { sequence: '1', monotonicNs: '10', kind: 'request', symbol: 'fixture.Controller.handle', fieldTruncations: [] },
      { sequence: '2', monotonicNs: '20', kind: 'recording_event_kind:gap', symbol: null, fieldTruncations: [{ field: 'symbol', originalBytes: '300', representation: 'truncated' }] },
    ];
    vi.mocked(fetch).mockImplementation((input: RequestInfo | URL) => {
      const path = route(input);
      if (path === '/api/v1/auth/exchange') return Promise.resolve(response({ authenticated: true }));
      if (path.startsWith('/api/v1/endpoints?')) return Promise.resolve(response(endpoints));
      if (path.includes(`/endpoints/${operationA}/recordings`)) return Promise.resolve(response({ ...linked, items: [linked.items[0], { ...linked.items[0], recordingId: recordingB }] }));
      if (path.startsWith(`/api/v1/recordings/${recordingA}?limit=200&cursor=`)) return Promise.resolve(response({ ...detail(recordingA), nextCursor: null, events: [{ sequence: '3', monotonicNs: '30', kind: 'method', symbol: 'fixture.Service.call', fieldTruncations: [] }] }));
      if (path.startsWith(`/api/v1/recordings/${recordingA}?limit=200`)) return Promise.resolve(response({ ...detail(recordingA), nextCursor: 'recording-a-next', events: firstEvents }));
      if (path.startsWith(`/api/v1/recordings/${recordingB}?limit=200`)) return Promise.resolve(response(detail(recordingB, 'recording-b-only')));
      throw new Error(`Unexpected request ${path}`);
    });
    render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: /POST \/orders Component: spring-fixture Binding: default observed/ }));
    fireEvent.click(await screen.findByRole('button', { name: new RegExp(recordingA) }));
    await screen.findByText('fixture.Controller.handle');
    fireEvent.keyDown(window, { key: 'ArrowDown', altKey: true });
    expect(await screen.findByText('recording_event_kind:gap')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Event 2 selected');
    fireEvent.click(screen.getByRole('button', { name: /recording_event_kind:gap/ }));
    expect(screen.getByText('symbol truncated · 300 bytes')).toBeInTheDocument();
    expect(screen.getByText('Source unavailable for this capture')).toBeInTheDocument();
    expect(screen.getByText('Values were not projected')).toBeInTheDocument();
    expect(screen.getByText('Duration unavailable for this capture')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('tab', { name: 'events' }));
    fireEvent.click(screen.getByRole('button', { name: 'Load next window' }));
    expect(await screen.findByText('fixture.Service.call')).toBeInTheDocument();
    expect(vi.mocked(fetch).mock.calls.some(([input]) => route(input as RequestInfo | URL) === `/api/v1/recordings/${recordingA}?limit=200&cursor=recording-a-next`)).toBe(true);
    fireEvent.click(screen.getByRole('tab', { name: 'recordings' }));
    fireEvent.click(screen.getByRole('button', { name: new RegExp(recordingB) }));
    expect(await screen.findByText('recording-b-only')).toBeInTheDocument();
    expect(screen.queryByText('fixture.Service.call')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Load next window' })).not.toBeInTheDocument();
  });

  it('bounds accumulated pages without losing continuation cursors', () => {
    let recordings = Array.from({ length: 500 }, (_, index) => `recording-${index}`);
    let events = Array.from({ length: 2_000 }, (_, index) => `event-${index + 1}`);
    let recordingReleased = 0;
    let eventReleased = 0;
    let recordingCursor: string | null = null;
    let eventCursor: string | null = null;
    for (let page = 0; page < 100; page += 1) {
      const recordingPage = retainPage(recordings, Array.from({ length: 50 }, (_, index) => `recording-${500 + page * 50 + index}`), 500, `recording-cursor-${page + 1}`);
      recordings = recordingPage.items;
      recordingReleased += recordingPage.released;
      recordingCursor = recordingPage.nextCursor;
      const eventPage = retainPage(events, Array.from({ length: 200 }, (_, index) => `event-${2_000 + page * 200 + index + 1}`), 2_000, `event-cursor-${page + 1}`);
      events = eventPage.items;
      eventReleased += eventPage.released;
      eventCursor = eventPage.nextCursor;
    }
    expect(recordings).toHaveLength(500);
    expect(events).toHaveLength(2_000);
    expect(recordings[0]).toBe('recording-5000');
    expect(events[0]).toBe('event-20001');
    expect(recordingReleased).toBe(5_000);
    expect(eventReleased).toBe(20_000);
    expect(recordingCursor).toBe('recording-cursor-100');
    expect(eventCursor).toBe('event-cursor-100');
  });
});
