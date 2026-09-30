/// <reference types="vite/client" />
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './main';
import { retainPage } from './retained-page';

describe('recording viewer', () => {
  beforeEach(() => {
    window.location.hash = '#token=test-bootstrap';
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/auth/exchange')) return new Response('{"authenticated":true}', { status: 200 });
      if (url.includes('/api/v1/recordings?')) return new Response(JSON.stringify({ recordings: [{
        recordingId: '018f0000-0000-7000-8000-000000000001', status: 'recording', openedAt: '2026-09-30T10:00:00Z', segmentCount: '1', eventCount: '2', incompleteEvidence: [],
      }], nextAfter: null }), { status: 200 });
      return new Response(JSON.stringify({
        status: 'recording', segmentCount: '1', incompleteEvidence: [], nextCursor: url.includes('cursor=') ? null : 'v1.next',
        unavailable: { source: 'unavailable', values: 'unavailable', completion: 'unavailable' },
        events: url.includes('cursor=')
          ? [{ sequence: '3', monotonicNs: '30', kind: 'method', symbol: 'fixture.Service.call', fieldTruncations: [] }]
          : [
            { sequence: '1', monotonicNs: '10', kind: 'recording_event_kind:very_long_technical_label_that_must_wrap_'.repeat(2), symbol: 'fixture.Controller.handle', fieldTruncations: [{ field: 'symbol', originalBytes: '300', representation: 'truncated' }] },
            { sequence: '2', monotonicNs: '20', kind: 'recording_event_kind:gap', symbol: null, fieldTruncations: [] },
          ],
      }), { status: 200 });
    }));
  });

  afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

  it('authenticates, selects persisted events, announces unavailable evidence, and navigates by keyboard', async () => {
    render(<App />);
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.length).toBeGreaterThanOrEqual(3));
    expect(await screen.findByText('fixture.Controller.handle')).toBeInTheDocument();
    const statusMark = document.querySelector('.status-mark');
    expect(statusMark).toHaveClass('status-mark', 'status-mark--recording');
    expect(statusMark).not.toHaveClass('recording');
    const longKind = screen.getByText('recording_event_kind:very_long_technical_label_that_must_wrap_'.repeat(2));
    expect(longKind).toHaveAttribute('title', longKind.textContent);
    expect(screen.getByText('Source unavailable for this capture')).toBeInTheDocument();
    expect(screen.getByText('Values were not projected')).toBeInTheDocument();
    expect(screen.getByText('Duration unavailable for this capture')).toBeInTheDocument();
    expect(screen.getByText('symbol truncated · 300 bytes')).toBeInTheDocument();
    fireEvent.keyDown(window, { key: 'ArrowDown', altKey: true });
    expect(await screen.findByText('recording_event_kind:gap')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /recording_event_kind:gap/ })).toHaveClass('gap-event');
    fireEvent.click(screen.getByRole('button', { name: 'Load next window' }));
    expect(await screen.findByText('fixture.Service.call')).toBeInTheDocument();
    expect(screen.getByText('3 ordered events')).toBeInTheDocument();
    expect(window.location.hash).toBe('');
  });

  it('renders explicit empty and error states', async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      if (String(input).includes('/auth/exchange')) return new Response('{}', { status: 200 });
      return new Response(JSON.stringify({ recordings: [], nextAfter: null }), { status: 200 });
    });
    render(<App />);
    expect(await screen.findByText('No recordings yet')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText('No recording selected')).toBeInTheDocument());
  });

  it('renders a safe request error', async () => {
    vi.mocked(fetch).mockImplementation(async (input: RequestInfo | URL) => {
      if (String(input).includes('/auth/exchange')) return new Response('{}', { status: 200 });
      return new Response(JSON.stringify({ detail: 'Persisted recording could not be verified', requestId: 'request-1' }), { status: 422 });
    });
    render(<App />);
    const alerts = await screen.findAllByRole('alert');
    expect(alerts.length).toBeGreaterThan(0);
    expect(alerts[0]).toHaveTextContent('Could not load persisted evidence');
  });

  it('marks an expired session after an authenticated API request', async () => {
    vi.mocked(fetch).mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/auth/exchange')) return new Response('{}', { status: 200 });
      if (url.includes('/api/v1/recordings?')) return new Response(JSON.stringify({ recordings: [{
        recordingId: '018f0000-0000-7000-8000-000000000001', status: 'recording', openedAt: '2026-09-30T10:00:00Z', segmentCount: '1', eventCount: '1', incompleteEvidence: [],
      }] }), { status: 200 });
      return new Response(JSON.stringify({ detail: 'Viewer session is missing or expired' }), { status: 401 });
    });
    render(<App />);
    expect(await screen.findByText('Viewer session expired')).toBeInTheDocument();
  });

  it('ignores an older detail response after a newer recording selection', async () => {
    const recordingA = '018f0000-0000-7000-8000-000000000001';
    const recordingB = '018f0000-0000-7000-8000-000000000002';
    let resolveA: ((response: Response) => void) | undefined;
    const requestUrls: string[] = [];
    vi.mocked(fetch).mockImplementation((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/auth/exchange')) return Promise.resolve(new Response('{}', { status: 200 }));
      if (url.includes('/api/v1/recordings?')) return Promise.resolve(new Response(JSON.stringify({ recordings: [
        { recordingId: recordingA, status: 'recording', openedAt: '2026-09-30T10:00:00Z', segmentCount: '1', eventCount: '1', incompleteEvidence: [] },
        { recordingId: recordingB, status: 'recording', openedAt: '2026-09-30T10:01:00Z', segmentCount: '1', eventCount: '2', incompleteEvidence: [] },
      ], nextAfter: null }), { status: 200 }));
      requestUrls.push(url);
      if (url.includes(recordingA)) return new Promise((resolve) => { resolveA = resolve; });
      const event = url.includes('cursor=b-next')
        ? { sequence: '2', monotonicNs: '20', kind: 'request', symbol: 'recording-b-second', fieldTruncations: [] }
        : { sequence: '1', monotonicNs: '10', kind: 'request', symbol: 'recording-b-first', fieldTruncations: [] };
      return Promise.resolve(new Response(JSON.stringify({
        recordingId: recordingB, status: 'recording', segmentCount: '1', incompleteEvidence: [],
        nextCursor: url.includes('cursor=b-next') ? null : 'b-next',
        unavailable: { source: 'unavailable', values: 'unavailable', completion: 'unavailable' },
        events: [event],
      }), { status: 200 }));
    });

    render(<App />);
    await waitFor(() => expect(requestUrls.some((url) => url.includes(recordingA))).toBe(true));
    fireEvent.click(screen.getByRole('button', { name: new RegExp(recordingB) }));
    expect(await screen.findByText('recording-b-first')).toBeInTheDocument();
    const liveRegion = document.querySelector('[aria-live="polite"]');
    expect(liveRegion).toHaveTextContent('1 events available for selection');

    await act(async () => {
      resolveA?.(new Response(JSON.stringify({
        recordingId: recordingA, status: 'recording', segmentCount: '1', incompleteEvidence: [], nextCursor: 'a-next',
        unavailable: { source: 'unavailable', values: 'unavailable', completion: 'unavailable' },
        events: [{ sequence: '1', monotonicNs: '10', kind: 'request', symbol: 'stale-recording-a', fieldTruncations: [] }],
      }), { status: 200 }));
    });
    expect(screen.getByRole('heading', { name: recordingB })).toBeInTheDocument();
    expect(screen.getByText('recording-b-first')).toBeInTheDocument();
    expect(screen.queryByText('stale-recording-a')).not.toBeInTheDocument();
    expect(liveRegion).toHaveTextContent('1 events available for selection');

    fireEvent.click(screen.getByRole('button', { name: 'Load next window' }));
    expect(await screen.findByText('recording-b-second')).toBeInTheDocument();
    expect(requestUrls.some((url) => url.includes(`/api/v1/recordings/${recordingB}?limit=200&cursor=b-next`))).toBe(true);
  });

  it('bounds long-lived page accumulation without losing cursor continuation', () => {
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
    expect(recordings.at(-1)).toBe('recording-5499');
    expect(events.at(-1)).toBe('event-22000');
    expect(recordings.length === 500 && recordingReleased > 0).toBe(true);
    expect(events.length === 2_000 && eventReleased > 0).toBe(true);
    expect(recordingCursor).toBe('recording-cursor-100');
    expect(eventCursor).toBe('event-cursor-100');
  });

});
