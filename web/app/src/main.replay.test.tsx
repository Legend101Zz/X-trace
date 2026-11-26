/// <reference types="vite/client" />
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './main';

const operationA = '018f0000-0000-7000-8000-000000000001';
const recordingA = '018f0000-0000-7000-8000-000000000011';
const recordingB = '018f0000-0000-7000-8000-000000000012';
const runtimeSessionId = '018f0000-0000-7000-8000-000000000021';
const sessionContext = { runtimeSessionId, rejectedRequests: null as string | null };

const endpoints = { items: [{ operationId: operationA, projectId: 'p', applicationComponent: 'svc', binding: 'default', method: 'POST', routeTemplate: '/orders', observation: 'observed', observationPolicy: 'pol' }], nextCursor: null };
const linked = { items: [{ recordingId: recordingA, status: 'complete', completion: 'complete', openedAt: '2026-10-03T10:00:00Z', segmentCount: '1', eventCount: '4', firstSequence: '1', lastSequence: '4', incompleteEvidence: [], sessionContext, operationId: operationA, observationPolicy: 'pol', unmatchedReason: null }], nextCursor: null };

const none = { state: 'boundary' };
const nav = (over: Record<string, unknown>) => ({ previous: none, next: none, into: none, over: none, out: none, ...over });
const ev = (n: number, parent: string | null, symbol: string, navigation: object) => ({ sequence: String(n), frameId: `f${n}` as string | null, eventId: `event-${n}`, navigation, monotonicNs: String(n * 10), kind: 'method', symbol, parentFrameId: parent, sourceBinding: 'unspecified', fieldTruncations: [], exception: null as { exceptionType: string | null } | null });

const events = [
  ev(1, null, 'Controller.create', nav({ next: { state: 'target', frameId: 'f2' }, into: { state: 'target', frameId: 'f2' } })),
  ev(2, 'f1', 'Repo.save', nav({ previous: { state: 'target', frameId: 'f1' }, next: { state: 'target', frameId: 'f3' }, out: { state: 'target', frameId: 'f1' } })),
  ev(3, 'f1', 'Audit.log', nav({ previous: { state: 'target', frameId: 'f2' }, next: { state: 'target', frameId: 'f9-outside' }, out: { state: 'target', frameId: 'f1' } })),
  ev(4, 'f3', 'Audit.write', nav({ previous: { state: 'target', frameId: 'f3' }, into: { state: 'target', frameId: 'f9-outside' } })),
];

const detail = {
  recordingId: recordingA, status: 'complete', completion: 'complete',
  adapterSummary: null as null | { Redacted: { rule_id: string; shape_hint: unknown } },
  capacity: null as null | { eventCap: number; eventCount: number; capacityDroppedEvents: string; dropsByPriority: Record<string, string> },
  durationNs: '20' as string | null, limitations: [] as string[], dropCountsByPriority: {}, segmentCount: '1', incompleteEvidence: [] as string[], nextCursor: null as string | null, prevCursor: null as string | null,
  sessionContext,
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
  await within(screen.getAllByRole('tabpanel', { name: 'Steps' }).find((panel) => panel.id === 'events-panel')!).findByText('Controller.create');
  fireEvent.click(within(screen.getByRole('tablist', { name: 'Viewer panes' })).getByRole('tab', { name: 'Steps' }));
}

const inspector = () => screen.getByRole('tabpanel', { name: 'Inspector', hidden: true });

describe('replay wiring in the app', () => {
  // jsdom 26 reflects dialog.open but has no showModal/close. These cases
  // exercise app shortcuts and preferences. Chromium exercises native modality.
  const dialogPrototype = HTMLDialogElement.prototype;
  const missingModal = typeof dialogPrototype.showModal !== 'function';
  const missingClose = typeof dialogPrototype.close !== 'function';
  beforeAll(() => {
    if (missingModal) Object.defineProperty(dialogPrototype, 'showModal', {
      configurable: true, value(this: HTMLDialogElement) { this.open = true; },
    });
    if (missingClose) Object.defineProperty(dialogPrototype, 'close', {
      configurable: true, value(this: HTMLDialogElement) { this.open = false; },
    });
  });
  afterAll(() => {
    if (missingModal) Reflect.deleteProperty(dialogPrototype, 'showModal');
    if (missingClose) Reflect.deleteProperty(dialogPrototype, 'close');
  });

  let responseDetail = detail;
  const continuationPages = new Map<string, typeof detail>();
  const heldContinuations = new Map<string, Promise<Response>>();
  let responseLinked = linked;
  let secondDetail: typeof detail | null = null;
  beforeEach(() => {
    responseDetail = detail;
    continuationPages.clear();
    heldContinuations.clear();
    responseLinked = linked;
    secondDetail = null;
    window.history.replaceState(null, '', '/viewer#token=t');
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = route(input);
      if (path === '/api/v1/auth/exchange') return json({ authenticated: true });
      if (path.startsWith('/api/v1/endpoints?')) return json(endpoints);
      if (path.includes('/recordings') && path.includes('/endpoints/')) return json(responseLinked);
      if (path.startsWith(`/api/v1/recordings/${recordingB}?`) && secondDetail) return json(secondDetail);
      if (path.startsWith('/api/v1/recordings/')) {
        const cursor = new URL(path, window.location.origin).searchParams.get('cursor');
        const held = cursor !== null ? heldContinuations.get(cursor) : undefined;
        if (held) return held;
        return json(cursor !== null ? continuationPages.get(cursor) ?? responseDetail : responseDetail);
      }
      throw new Error(`Unexpected request ${path}`);
    }));
  });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); localStorage.removeItem('xtrace.viewer.appearance'); });

  it('uses explicit Replay/Pause shortcuts while preserving native inputs and dialog keys', async () => {
    await openRecording();
    const replay = screen.getByRole('button', { name: 'Replay' });
    const search = document.getElementById('request-search')!;
    fireEvent.keyDown(search, { altKey: true, code: 'KeyP' });
    expect(replay).toHaveAttribute('aria-pressed', 'false');
    replay.focus();
    fireEvent.keyDown(replay, { altKey: true, code: 'KeyP', key: 'π' });
    expect(screen.getByRole('button', { name: 'Pause' })).toHaveFocus();
    fireEvent.keyDown(document.body, { key: 'Escape' });
    expect(screen.getByRole('button', { name: 'Replay' })).toHaveFocus();
    fireEvent.keyDown(document.body, { altKey: true, code: 'Comma' });
    expect(screen.getByRole('button', { name: 'Replay speed, 0.5×' })).toBeInTheDocument();
    fireEvent.keyDown(document.body, { altKey: true, code: 'Period' });
    expect(screen.getByRole('button', { name: 'Replay speed, 1×' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Settings' }));
    fireEvent.keyDown(screen.getByRole('combobox', { name: 'Default speed' }), { altKey: true, code: 'KeyP' });
    expect(document.querySelector('.replay-start')).toHaveAttribute('aria-pressed', 'false');
  });

  it('pauses playback and keeps Settings available when Help starts the tour', async () => {
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: 'Replay' }));
    expect(screen.getByRole('button', { name: 'Pause' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Help' }));
    expect(document.querySelector('.replay-start')).toHaveAttribute('aria-pressed', 'false');
    fireEvent.click(within(screen.getByRole('dialog', { name: 'Help' })).getByRole('button', { name: 'Take the 3-step tour' }));
    expect(screen.getByRole('dialog', { name: 'Find a recording' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Skip tour' }));
    fireEvent.click(screen.getByRole('button', { name: 'Settings' }));
    expect(screen.getByRole('combobox', { name: 'Default speed' })).toBeInTheDocument();
  });

  it('focuses the selected row on click or Alt+M, and keeps arrow navigation on the view tab', async () => {
    await openRecording();
    const tabs = screen.getByRole('tablist', { name: 'Replay view' });
    const steps = within(tabs).getByRole('tab', { name: 'Steps' });
    const map = within(tabs).getByRole('tab', { name: 'Map' });
    fireEvent.click(map);
    expect(screen.getByRole('treeitem', { selected: true })).toHaveFocus();
    fireEvent.keyDown(document.activeElement!, { altKey: true, code: 'KeyM' });
    expect(screen.getByRole('button', { name: /Controller\.create/ })).toHaveFocus();
    steps.focus();
    fireEvent.keyDown(steps, { key: 'ArrowRight' });
    expect(map).toHaveFocus();
    expect(map).toHaveAttribute('aria-selected', 'true');
    fireEvent.keyDown(map, { key: 'ArrowLeft' });
    expect(steps).toHaveFocus();
    expect(steps).toHaveAttribute('aria-selected', 'true');
    fireEvent.keyDown(steps, { key: 'End' });
    expect(map).toHaveFocus();
    expect(map).toHaveAttribute('aria-selected', 'true');
    fireEvent.keyDown(map, { key: 'Home' });
    expect(steps).toHaveFocus();
    expect(steps).toHaveAttribute('aria-selected', 'true');
  });

  it('leaves focus with a later view change or manual focus move while Go is queued', async () => {
    await openRecording();
    const callbacks: FrameRequestCallback[] = [];
    vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => callbacks.push(callback));
    const cancel = vi.fn();
    vi.stubGlobal('cancelAnimationFrame', cancel);
    const views = screen.getByRole('tablist', { name: 'Replay view' });
    const queueGo = (sequence: string) => {
      const count = callbacks.length;
      fireEvent.keyDown(document.activeElement!, { altKey: true, code: 'KeyJ' });
      const input = screen.getByRole('textbox', { name: 'Go to step number' });
      fireEvent.change(input, { target: { value: sequence } });
      fireEvent.submit(input.closest('form')!);
      expect(callbacks).toHaveLength(count + 1);
      expect(document.querySelector('.event[aria-current="true"] .event-seq')).toHaveTextContent(sequence);
      return { frame: callbacks[count], handle: count + 1 };
    };

    const first = queueGo('2');
    fireEvent.click(within(views).getByRole('tab', { name: 'Map' }));
    const selectedFrame = screen.getByRole('treeitem', { selected: true });
    expect(selectedFrame).toHaveFocus();
    expect(cancel).toHaveBeenCalledWith(first.handle);
    act(() => first.frame(0));
    expect(selectedFrame).toHaveFocus();

    fireEvent.click(within(views).getByRole('tab', { name: 'Steps' }));
    const next = queueGo('3');
    const replay = screen.getByRole('button', { name: 'Replay' });
    act(() => replay.focus());
    expect(replay).toHaveFocus();
    expect(cancel).toHaveBeenCalledWith(next.handle);
    act(() => next.frame(0));
    expect(replay).toHaveFocus();
    expect(document.querySelector('.event[aria-current="true"] .event-seq')).toHaveTextContent('3');
  });

  it('keeps current speed separate from persisted defaults and applies the default on a new recording', async () => {
    localStorage.setItem('xtrace.viewer.appearance', JSON.stringify({ defaultSpeed: '2' }));
    responseLinked = { ...linked, items: [linked.items[0], { ...linked.items[0], recordingId: recordingB }] };
    secondDetail = { ...detail, recordingId: recordingB };
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: 'Replay speed, 2×' }));
    fireEvent.click(screen.getByRole('button', { name: '4×' }));
    fireEvent.click(screen.getByRole('button', { name: 'Settings' }));
    fireEvent.change(screen.getByRole('combobox', { name: 'Default speed' }), { target: { value: '0.5' } });
    fireEvent.keyDown(screen.getByRole('dialog', { name: 'Settings' }), { key: 'Escape' });
    expect(screen.getByRole('button', { name: 'Replay speed, 4×' })).toBeInTheDocument();
    expect(JSON.parse(localStorage.getItem('xtrace.viewer.appearance')!).defaultSpeed).toBe('0.5');
    fireEvent.click(screen.getByRole('button', { name: new RegExp(recordingB) }));
    await screen.findByRole('button', { name: 'Replay speed, 0.5×' });
    expect(screen.getByRole('button', { name: 'Replay' })).toHaveAttribute('aria-pressed', 'false');
  });

  it('keeps a filtered shared-frame selection through Map, refresh and recording tab restoration', async () => {
    responseDetail = { ...detail, events: [
      { ...events[0], kind: 'recording_event_kind:frame_enter' },
      { ...events[1], kind: 'recording_event_kind:line_cursor', frameId: events[0].frameId },
      { ...events[2], kind: 'recording_event_kind:frame_exit' },
      { ...events[3], kind: 'recording_event_kind:gap', frameId: null },
    ] };
    responseLinked = { ...linked, items: [linked.items[0], { ...linked.items[0], recordingId: recordingB }] };
    secondDetail = { ...detail, recordingId: recordingB };
    render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: /POST \/orders/ }));
    fireEvent.click(await screen.findByRole('button', { name: new RegExp(recordingA) }));
    await screen.findByRole('button', { name: /Called Controller\.create/ });
    fireEvent.click(within(screen.getByRole('tablist', { name: 'Viewer panes' })).getByRole('tab', { name: 'Steps' }));
    fireEvent.keyDown(document.body, { altKey: true, code: 'KeyJ' });
    const sequence = screen.getByRole('textbox', { name: 'Go to step number' });
    fireEvent.change(sequence, { target: { value: '2' } });
    fireEvent.submit(sequence.closest('form')!);
    const exactSelected = () => document.querySelector('.event[aria-current="true"] .event-seq');
    expect(exactSelected()).toHaveTextContent('2');

    fireEvent.keyDown(document.body, { altKey: true, code: 'KeyQ' });
    fireEvent.click(screen.getByRole('button', { name: 'Not recorded' }));
    const steps = screen.getByRole('list', { name: 'Loaded replay steps' });
    expect(steps.querySelectorAll('.event')).toHaveLength(2);
    expect(exactSelected()).toHaveTextContent('2');
    expect(screen.getByText(/showing 2 of 4 loaded steps/)).toBeInTheDocument();
    fireEvent.click(within(screen.getByRole('tablist', { name: 'Replay view' })).getByRole('tab', { name: 'Map' }));
    expect(screen.getByRole('region', { name: 'Recording summary' })).toHaveTextContent('Event sequence 2');
    fireEvent.click(within(screen.getByRole('tablist', { name: 'Replay view' })).getByRole('tab', { name: 'Steps' }));
    expect(exactSelected()).toHaveTextContent('2');
    fireEvent.click(within(screen.getAllByRole('tabpanel', { name: 'Steps' }).find((panel) => panel.id === 'events-panel')!).getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(exactSelected()).toHaveTextContent('2'));
    expect(screen.getByText(/showing 2 of 4 loaded steps/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: new RegExp(recordingB) }));
    await waitFor(() => expect(screen.getByRole('region', { name: 'Recording summary' })).toHaveTextContent('Event sequence 1'));
    fireEvent.click(screen.getByRole('tab', { name: new RegExp(recordingA) }));
    await waitFor(() => expect(exactSelected()).toHaveTextContent('2'));
    expect(screen.getByText(/showing 2 of 4 loaded steps/)).toBeInTheDocument();
  });

  it('returns focus to persistent Tools when clearing the filter removes Show all steps', async () => {
    await openRecording();
    const tools = screen.getByRole('button', { name: 'Tools' });
    tools.focus();
    fireEvent.keyDown(tools, { altKey: true, code: 'KeyQ' });
    fireEvent.click(screen.getByRole('button', { name: 'Not recorded' }));
    const selected = () => document.querySelector('.event[aria-current="true"] .event-seq');
    const sequence = selected()?.textContent;
    const clear = screen.getByRole('button', { name: 'Show all steps' });
    clear.focus();
    fireEvent.click(clear);
    expect(screen.queryByRole('button', { name: 'Show all steps' })).not.toBeInTheDocument();
    expect(tools).toHaveFocus();
    expect(selected()?.textContent).toBe(sequence);
  });

  it.each([
    [null, 'agent capacity rejections not observed'],
    ['0', '0 requests were not recorded due to agent capacity (cumulative as last reported)'],
    ['7', '7 requests were not recorded due to agent capacity (cumulative as last reported)'],
  ])('shows session count %s separately in the banner and inspector', async (rejectedRequests, message) => {
    responseDetail = { ...detail, sessionContext: { runtimeSessionId, rejectedRequests } };
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: /Controller\.create/ }));
    const banner = screen.getByRole('region', { name: 'Recording outcome' });
    const text = `Session capture context (session ${runtimeSessionId}): ${message}`;
    expect(within(banner).getByText('Recording complete: finish evidence was verified.')).toBeInTheDocument();
    expect(banner).toHaveClass('outcome-banner--complete');
    expect(within(banner).getByText(text)).toBeInTheDocument();
    expect(within(banner).queryByText(/Persisted incomplete evidence:/)).not.toBeInTheDocument();
    expect(within(inspector()).getByText('Session context')).toBeInTheDocument();
    expect(within(inspector()).getByText(text)).toBeInTheDocument();
    expect(within(inspector()).queryByText(/Persisted incomplete evidence:/)).not.toBeInTheDocument();
  });

  it('renders the outcome banner from the real outcome shape', async () => {
    await openRecording();
    const banner = screen.getByRole('region', { name: 'Recording outcome' });
    expect(within(banner).getByText('Response status 500 (as reported by the adapter)')).toBeInTheDocument();
    expect(within(banner).getByText('Exception java.lang.IllegalStateException: boom')).toBeInTheDocument();
  });

  it.each([
    { limitations: ['capture_policy_not_armed'], durationNs: '4199999', label: 'Standard', duration: '4.1 ms' },
    { limitations: [], durationNs: null, label: 'Capture', duration: 'Duration unavailable' },
    { limitations: ['future_limitation'], durationNs: '0', label: 'Capture', duration: '0 ns' },
  ])('shows recording bar evidence for $limitations with duration $durationNs', async ({ limitations, durationNs, label, duration }) => {
    const withLocal = events.map(event => ({ ...event, bindings: [{ name: 'observed', role: 'local',
      nameOrigin: 'declared', value: { state: 'captured', preview: 'seen' } }] }));
    responseDetail = { ...detail, durationNs, limitations, events: withLocal };
    await openRecording();
    const bar = screen.getByRole('region', { name: 'Recording summary' });
    const pill = within(bar).getByLabelText('Capture evidence');
    expect(pill).toHaveTextContent(label);
    expect(bar.querySelector('.recording-duration-value')).toHaveTextContent(duration);
    const panel = pill.parentElement!;
    expect(panel).toHaveTextContent(label === 'Standard'
      ? 'Focused capture was not armed; relaunch with focused capture to record this.'
      : 'Capture mode unavailable for this recording.');
    expect([...panel.querySelectorAll('li')].map(item => item.textContent)).toEqual(limitations);
    expect(panel).not.toHaveTextContent('seen');
  });

  it('shows the selected throw type separately from the framework outcome wrapper', async () => {
    responseDetail = {
      ...detail,
      outcome: { ...detail.outcome, exception: { exceptionType: 'jakarta.servlet.ServletException', message: 'wrapper' } },
      events: events.map((event, index) => index === 1 ? {
        ...event,
        kind: 'recording_event_kind:frame_throw',
        exception: {
          exceptionType: 'org.example.ApplicationException',
          message: 'private-message-canary',
          stackFrames: ['private-stack-canary'],
        },
      } : event),
    };
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: /Repo\.save/ }));
    expect(within(inspector()).getByText('org.example.ApplicationException')).toBeInTheDocument();
    expect(within(inspector()).getByText(/cause chain not observed/)).toBeInTheDocument();
    expect(within(inspector()).queryByText(/jakarta.servlet.ServletException/)).not.toBeInTheDocument();
    expect(within(inspector()).queryByText(/private-message-canary|private-stack-canary/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Controller\.create/ }));
    expect(within(inspector()).queryByText(/Thrown exception:/)).not.toBeInTheDocument();
  });

  it('names a missing throw type without substituting the recording outcome', async () => {
    responseDetail = { ...detail, events: events.map((event, index) => index === 1 ? {
      ...event, kind: 'recording_event_kind:frame_throw', exception: { exceptionType: null },
    } : event) };
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: /Repo\.save/ }));
    expect(within(inspector()).getByText('type not observed')).toBeInTheDocument();
    expect(within(inspector()).queryByText(/java.lang.IllegalStateException/)).not.toBeInTheDocument();
  });

  it('keeps one selection across Linear -> Canvas -> inspector -> Linear', async () => {
    await openRecording();
    // Linear click selects event 2 (Repo.save).
    fireEvent.click(screen.getByRole('button', { name: /Repo\.save/ }));
    expect(within(inspector()).getByText('event-2')).toBeInTheDocument();
    // Switch to Canvas: the same frame is the selected tree item.
    fireEvent.click(within(screen.getByRole('tablist', { name: 'Replay view' })).getByRole('tab', { name: 'Map' }));
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
    fireEvent.click(within(screen.getByRole('tablist', { name: 'Replay view' })).getByRole('tab', { name: 'Steps' }));
    expect(screen.getByRole('button', { name: /Audit\.write/ })).toHaveAttribute('aria-current', 'true');
  });

  it('navigation buttons select the server-resolved target frame', async () => {
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: /Controller\.create/ }));
    const toolbar = screen.getByRole('group', { name: 'Replay navigation' });
    fireEvent.click(within(toolbar).getByRole('button', { name: 'Step in' }));
    expect(within(inspector()).getByText('event-2')).toBeInTheDocument();
    fireEvent.click(within(toolbar).getByRole('button', { name: 'Step out' }));
    expect(within(inspector()).getByText('event-1')).toBeInTheDocument();
  });

  it('says why a target outside the loaded window cannot be reached, in the inspector', async () => {
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: /Audit\.log/ }));
    expect(within(inspector()).getByRole('button', { name: 'Next frame' })).toBeDisabled();
    expect(within(inspector()).getByText(/outside the loaded window/)).toBeInTheDocument();
  });

  const live = () => screen.getByRole('status', { hidden: true });

  it('keeps one Steps tab stop and moves focus with adjacent-event keyboard navigation', async () => {
    await openRecording();
    const first = screen.getByRole('button', { name: /Controller\.create/ });
    const second = screen.getByRole('button', { name: /Repo\.save/ });
    expect(first).toHaveAttribute('tabindex', '0');
    expect(second).toHaveAttribute('tabindex', '-1');
    first.focus();
    fireEvent.keyDown(first, { key: 'ArrowDown' });
    expect(second).toHaveFocus();
    expect(second).toHaveAttribute('aria-current', 'true');
    expect(first).toHaveAttribute('tabindex', '-1');
    expect(live()).toHaveTextContent('Event 2 selected');
  });

  it('matches physical Option shortcuts while preserving native search editing', async () => {
    await openRecording();
    const search = screen.getByRole('searchbox', { name: 'Search loaded requests' });
    expect(fireEvent.keyDown(search, { key: 'ˆ', code: 'KeyI', altKey: true })).toBe(true);
    expect(screen.getByRole('button', { name: /Controller\.create/ })).toHaveAttribute('aria-current', 'true');

    fireEvent.keyDown(window, { key: 'ˆ', code: 'KeyI', altKey: true });
    expect(within(inspector()).getByText('event-2')).toBeInTheDocument();
    fireEvent.keyDown(window, { key: 'µ', code: 'KeyM', altKey: true });
    const selection = screen.getByRole('treeitem', { selected: true });
    expect(selection).toHaveTextContent('Repo.save');
    await waitFor(() => expect(selection).toHaveFocus());
    fireEvent.keyDown(selection, { key: 'µ', code: 'KeyM', altKey: true });
    const row = screen.getByRole('button', { name: /Repo\.save/ });
    expect(row).toHaveAttribute('aria-current', 'true');
    await waitFor(() => expect(row).toHaveFocus());
  });

  it('shows and announces an unloaded frame target once without moving Steps selection', async () => {
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: /Audit\.write/ }));
    const toolbar = screen.getByRole('group', { name: 'Replay navigation' });
    const into = within(toolbar).getByRole('button', { name: 'Step in' });
    expect(into).toHaveAttribute('aria-disabled', 'true');
    fireEvent.focus(into);
    fireEvent.mouseEnter(within(toolbar).getByRole('button', { name: /^Next$/ }));
    expect(toolbar.querySelector('.replay-reason')).toHaveTextContent(/outside the loaded window/);
    fireEvent.keyDown(into, { key: 'i', altKey: true });
    expect(live()).toHaveTextContent(/outside the loaded window/);
    expect(document.querySelectorAll('[aria-live="polite"]')).toHaveLength(1);
    expect(within(inspector()).getByText('event-4')).toBeInTheDocument();
  });

  it('announces an out-of-window Canvas key target in the live region', async () => {
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: /Audit\.write/ }));
    fireEvent.click(within(screen.getByRole('tablist', { name: 'Replay view' })).getByRole('tab', { name: 'Map' }));
    fireEvent.keyDown(screen.getByRole('tree'), { key: 'ArrowRight' });
    await waitFor(() => expect(live()).toHaveTextContent(/outside the loaded window/));
  });

  it('announces a boundary in the live region', async () => {
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: /Audit\.log/ }));
    fireEvent.click(within(screen.getByRole('tablist', { name: 'Replay view' })).getByRole('tab', { name: 'Map' }));
    fireEvent.keyDown(screen.getByRole('tree'), { key: 'ArrowRight' });
    await waitFor(() => expect(live()).toHaveTextContent(/Boundary: no further frame in this direction/));
  });

  it('announces Selected event N after an in-window Canvas key step', async () => {
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: /Controller\.create/ }));
    fireEvent.click(within(screen.getByRole('tablist', { name: 'Replay view' })).getByRole('tab', { name: 'Map' }));
    fireEvent.keyDown(screen.getByRole('tree'), { key: 'ArrowRight' });
    await waitFor(() => expect(live()).toHaveTextContent('Selected event 2'));
  });

  const showEvents = () => fireEvent.click(within(screen.getByRole('tablist', { name: 'Viewer panes' })).getByRole('tab', { name: 'Steps' }));
  const refreshEvents = () => {
    showEvents();
    fireEvent.click(within(screen.getAllByRole('tabpanel', { name: 'Steps' }).find((panel) => panel.id === 'events-panel')!).getByRole('button', { name: 'Refresh' }));
  };

  it('preserves the exact same-frame event through Canvas, reordering, and a missing window', async () => {
    const line = { ...ev(5, 'f1', 'Repo.line', nav({})), frameId: 'f2' };
    responseDetail = { ...detail, events: [...events, line] };
    await openRecording();

    fireEvent.click(screen.getByRole('button', { name: /Repo\.line/ }));
    expect(within(inspector()).getByText('event-5')).toBeInTheDocument();
    showEvents();
    fireEvent.click(within(screen.getByRole('tablist', { name: 'Replay view' })).getByRole('tab', { name: 'Map' }));
    const selectedFrame = screen.getByRole('treeitem', { selected: true });
    expect(selectedFrame).toHaveTextContent('Repo.save');
    fireEvent.click(selectedFrame);
    expect(within(inspector()).getByText('event-5')).toBeInTheDocument();
    fireEvent.click(within(screen.getByRole('tablist', { name: 'Replay view' })).getByRole('tab', { name: 'Steps' }));

    responseDetail = { ...detail, events: [events[1], line, events[0], ...events.slice(2)] };
    refreshEvents();
    await waitFor(() => expect(screen.getAllByRole('button', { name: /Repo\.line|Controller\.create/ })[0]).toHaveTextContent('Repo.line'));
    expect(screen.getByRole('button', { name: /Repo\.line/ })).toHaveAttribute('aria-current', 'true');
    expect(within(inspector()).getByText('event-5')).toBeInTheDocument();

    responseDetail = detail;
    refreshEvents();
    expect(await within(inspector()).findByText('Selected event is not in the loaded window.')).toBeInTheDocument();
    expect(within(inspector()).queryByText('event-2')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Repo\.save/ })).toHaveAttribute('aria-current', 'false');
    fireEvent.keyDown(window, { altKey: true, key: 'ArrowDown' });
    expect(within(inspector()).getByText('Selected event is not in the loaded window.')).toBeInTheDocument();

    responseDetail = { ...detail, events: [...events, line] };
    refreshEvents();
    expect(await within(inspector()).findByText('event-5')).toBeInTheDocument();
  });

  it.each([0, 100])('preserves the frame-less Canvas boundary and recording reset with %i extra frames', async (extra) => {
    const auditSequence = 4 + extra;
    const boundarySequence = auditSequence + 1;
    const audit = ev(auditSequence, 'f3', 'Audit.write', events[3].navigation);
    const frameLess = { ...ev(boundarySequence, null, 'Request boundary', nav({})), frameId: null };
    const added = Array.from({ length: extra }, (_, index) => ev(index + 4, 'f3', `Frame ${index}`, nav({})));
    responseLinked = { ...linked, items: [...linked.items, { ...linked.items[0], recordingId: recordingB }] };
    responseDetail = { ...detail, events: [...events.slice(0, 3), ...added, audit, frameLess] };
    await openRecording();

    if (extra) {
      const views = screen.getByRole('tablist', { name: 'Replay view' });
      fireEvent.click(within(views).getByRole('tab', { name: 'Map' }));
      const tree = screen.getByRole('tree');
      expect(within(tree).queryByRole('treeitem', { name: /Audit\.write/ })).not.toBeInTheDocument();
      fireEvent.keyDown(tree, { key: 'End' });
      expect(within(tree).getByRole('treeitem', { selected: true })).toHaveAttribute('data-key', audit.frameId);
      fireEvent.click(within(views).getByRole('tab', { name: 'Steps' }));
    }
    fireEvent.click(screen.getByRole('button', { name: /Audit\.write/ }));
    fireEvent.keyDown(window, { altKey: true, key: 'ArrowDown' });
    expect(within(inspector()).getByText(`event-${boundarySequence}`)).toBeInTheDocument();
    expect(live()).toHaveTextContent(`Event ${boundarySequence} selected`);
    const toolbar = screen.getByRole('group', { name: 'Replay navigation' });
    fireEvent.click(within(toolbar).getByRole('button', { name: 'Back' }));
    expect(within(inspector()).getByText(`event-${auditSequence}`)).toBeInTheDocument();
    fireEvent.click(within(toolbar).getByRole('button', { name: /^Next$/ }));
    expect(within(inspector()).getByText(`event-${boundarySequence}`)).toBeInTheDocument();
    showEvents();
    fireEvent.click(within(screen.getByRole('tablist', { name: 'Replay view' })).getByRole('tab', { name: 'Map' }));
    expect(screen.queryByRole('treeitem', { selected: true })).not.toBeInTheDocument();
    expect(screen.getByText('Frame ID unavailable for the selected event.')).toBeInTheDocument();
    expect(within(inspector()).getByText(`event-${boundarySequence}`)).toBeInTheDocument();
    const treeItems = screen.getAllByRole('treeitem');
    if (extra) expect(treeItems.length).toBeLessThan(added.length);
    const initialTreeItem = treeItems[0];
    initialTreeItem.focus();
    expect(initialTreeItem).toHaveFocus();
    fireEvent.keyDown(initialTreeItem, { altKey: true, key: 'ArrowDown' });
    expect(within(inspector()).getByText(`event-${boundarySequence}`)).toBeInTheDocument();
    expect(screen.queryByRole('treeitem', { selected: true })).not.toBeInTheDocument();
    expect(initialTreeItem).toHaveFocus();
    fireEvent.keyDown(initialTreeItem, { altKey: true, key: 'ArrowUp' });
    expect(within(inspector()).getByText(`event-${auditSequence}`)).toBeInTheDocument();
    const selectedTreeItem = screen.getByRole('treeitem', { selected: true });
    expect(selectedTreeItem).toHaveFocus();
    fireEvent.keyDown(selectedTreeItem, { altKey: true, key: 'ArrowDown' });
    expect(within(inspector()).getByText(`event-${boundarySequence}`)).toBeInTheDocument();
    fireEvent.click(within(screen.getByRole('tablist', { name: 'Replay view' })).getByRole('tab', { name: 'Steps' }));
    expect(screen.getByRole('button', { name: /Request boundary/ })).toHaveAttribute('aria-current', 'true');

    responseDetail = { ...detail, recordingId: recordingB };
    fireEvent.click(screen.getByRole('tab', { name: 'Requests' }));
    fireEvent.click(screen.getByRole('button', { name: new RegExp(recordingB) }));
    expect(await within(inspector()).findByText('event-1')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Controller\.create/ })).toHaveAttribute('aria-current', 'true');
  });
  it('switches and closes recording tabs by keyboard while restoring the selected event', async () => {
    responseLinked = { ...linked, items: [...linked.items, { ...linked.items[0], recordingId: recordingB }] };
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: /Audit\.write/ }));
    expect(within(inspector()).getByText('event-4')).toBeInTheDocument();
    secondDetail = { ...detail, recordingId: recordingB, events: [{ ...events[0], eventId: 'other-recording-event' }] };
    fireEvent.click(screen.getByRole('tab', { name: 'Requests' }));
    fireEvent.click(screen.getByRole('button', { name: new RegExp(recordingB) }));
    expect(await within(inspector()).findByText('other-recording-event')).toBeInTheDocument();

    const tabs = screen.getByRole('tablist', { name: 'Open recordings' });
    const first = within(tabs).getByRole('tab', { name: new RegExp(recordingA) });
    const second = within(tabs).getByRole('tab', { name: new RegExp(recordingB) });
    second.focus();
    responseDetail = detail;
    fireEvent.keyDown(second, { key: 'ArrowLeft' });
    expect(first).toHaveFocus();
    expect(first).toHaveAttribute('aria-selected', 'true');
    expect(await within(inspector()).findByText('event-4')).toBeInTheDocument();

    fireEvent.keyDown(first, { key: 'Delete' });
    expect(within(tabs).queryByRole('tab', { name: new RegExp(recordingA) })).not.toBeInTheDocument();
    expect(second).toHaveAttribute('aria-selected', 'true');
    await waitFor(() => expect(second).toHaveFocus());
  });

  it('restores an accepted same-batch playback advance and its opaque page cursor after switching recordings', async () => {
    responseLinked = { ...linked, items: [...linked.items, { ...linked.items[0], recordingId: recordingB }] };
    responseDetail = { ...detail, events: [events[0]], nextCursor: 'page opaque+/=' };
    continuationPages.set('page opaque+/=', { ...detail, events: [events[1], events[2]], prevCursor: 'previous' });
    secondDetail = { ...detail, recordingId: recordingB };
    await openRecording();
    fireEvent.click(within(screen.getByRole('region', { name: 'Loaded event window' })).getByRole('button', { name: 'Load later' }));
    await screen.findByRole('button', { name: /Repo\.save/ });
    fireEvent.click(screen.getByRole('button', { name: /Repo\.save/ }));
    fireEvent.click(screen.getByRole('tab', { name: 'Requests' }));
    fireEvent.click(screen.getByRole('button', { name: new RegExp(recordingB) }));
    await within(inspector()).findByText('event-1');
    const tabs = screen.getByRole('tablist', { name: 'Open recordings' });
    fireEvent.click(within(tabs).getByRole('tab', { name: new RegExp(recordingA) }));
    await screen.findByRole('button', { name: /Repo\.save/ });
    const timeout = vi.spyOn(window, 'setTimeout');
    try {
      fireEvent.click(screen.getByRole('button', { name: 'Replay' }));
      const tick = timeout.mock.calls.filter(([, delay]) => delay === 0).at(-1)?.[0];
      expect(typeof tick).toBe('function');
      act(() => { (tick as () => void)(); fireEvent.click(within(tabs).getByRole('tab', { name: new RegExp(recordingB) })); });
      await within(inspector()).findByText('event-1');
      fireEvent.click(within(tabs).getByRole('tab', { name: new RegExp(recordingA) }));
      expect(await screen.findByRole('button', { name: /Audit\.log/ })).toHaveAttribute('aria-current', 'true');
      const requests = vi.mocked(fetch).mock.calls.map(([input]) => new URL(String(input), window.location.origin))
        .filter((url) => url.pathname === `/api/v1/recordings/${recordingA}`);
      expect(requests.at(-1)?.searchParams.get('cursor')).toBe('page opaque+/=');
    } finally { timeout.mockRestore(); }
  });
  it('numbers matched blank lines and shows private binding states without leaking payloads', async () => {
    const match = { path: 'Example.java', status: 'matched', startLine: 7, endLine: 9, excerpt: '\n  body();\n}', truncated: false };
    const bindings = [
      { name: 'safeLocal', role: 'local', nameOrigin: 'declared', value: { state: 'captured', preview: '<span>observed</span>' } },
      { name: 'arg0', role: 'argument', nameOrigin: 'synthesized', value: { state: 'truncated', preview: 'prefix' } },
      { name: 'hidden', role: 'local', nameOrigin: 'declared', value: { state: 'redacted', preview: 'PRIVATE-HIDDEN' } },
      { name: 'missing', role: 'local', nameOrigin: 'declared', value: { state: 'unavailable', reason: 'focused_capture_not_armed', preview: 'PRIVATE-MISSING' } },
      { name: 'dropped', role: 'return', nameOrigin: 'declared', value: { state: 'dropped', reason: 'value_budget', preview: 'PRIVATE-DROPPED' } },
    ];
    const range = { ...events[0], source: match, kind: 'recording_event_kind:frame_enter', sourceBinding: 'verified' };
    const cursor = {
      ...events[1], source: { ...match, truncated: true }, kind: 'recording_event_kind:line_cursor',
      sourceBinding: 'observed_unattested', line: 8, bindings,
    };
    const mismatch = {
      ...events[2], source: { ...match, status: 'mismatch', excerpt: 'PRIVATE-SOURCE' },
      kind: 'recording_event_kind:line_cursor', sourceBinding: 'verified', line: 8,
    };
    responseDetail = { ...detail, events: [range, cursor, mismatch] };
    render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: /POST \/orders/ }));
    fireEvent.click(await screen.findByRole('button', { name: new RegExp(recordingA) }));
    fireEvent.click(await screen.findByRole('button', { name: /Called Controller\.create/ }));
    const code = () => within(inspector()).getByRole('region', { name: 'Code', hidden: true });
    const rows = () => [...code().querySelectorAll('.source-row')];
    expect(rows().map((row) => row.getAttribute('data-source-line'))).toEqual(['7', '8', '9']);
    expect(rows()[0].querySelector('.source-text')?.textContent).toBe('');
    expect(code().querySelector('[aria-current="location"]')).toBeNull();

    fireEvent.keyDown(window, { key: 'ArrowDown', altKey: true });
    const active = code().querySelector('[aria-current="location"]');
    expect(active).toHaveAttribute('data-source-line', '8');
    expect(active?.querySelector('.source-inline')).toHaveTextContent('Local bindings at the recorded line cursor');
    expect(active?.querySelector('.source-inline')).toHaveTextContent('<span>observed</span>');
    expect(active?.querySelector('.source-inline')).not.toHaveTextContent('arg0');
    expect(active?.querySelector('.source-inline')).not.toHaveTextContent('before it ran');
    expect(within(code()).getByText('Source excerpt is bounded')).toBeInTheDocument();

    fireEvent.click(within(inspector()).getByRole('tab', { name: /^Values/ }));
    const values = within(inspector()).getByRole('region', { name: 'Values', hidden: true });
    expect([...values.querySelectorAll('[data-value-state]')].map((row) => row.getAttribute('data-value-state')))
      .toEqual(['captured', 'truncated', 'redacted', 'unavailable', 'dropped']);
    expect(values.querySelector('[data-value-state="redacted"] details')).toHaveTextContent('Value withheld by a redaction rule.');
    expect(values.querySelector('[data-value-state="truncated"]')).toHaveTextContent('prefix');
    expect(values.querySelector('img, script')).toBeNull();
    expect(inspector()).not.toHaveTextContent(/PRIVATE-/);

    fireEvent.keyDown(window, { key: 'ArrowDown', altKey: true });
    expect(rows()).toHaveLength(0);
    expect(within(code()).getByText('Recorded line cursor L8. No matching source row is available.')).toBeInTheDocument();
    expect(inspector()).not.toHaveTextContent('PRIVATE-SOURCE');
  });
  it('groups loaded reports and focuses the recorded frame-less gap without inventing step targets', async () => {
    const sentinel = { ...events[1], frameId: null, kind: 'recording_event_kind:gap',
      gap: { count: '9007199254740993', reason: 'line_budget' } };
    const event = { ...events[0], interaction: { method: 'GET', path: 'PRIVATE-WITHHELD-PATH' } };
    responseDetail = { ...detail, events: [event, sentinel],
      incompleteEvidence: ['gap_event_sequence:2', 'gap_event_sequence:12', 'future_persisted_code'] };
    await openRecording();
    fireEvent.click(screen.getByRole('tab', { name: 'Inspector' }));
    const details = within(inspector()).getByRole('tab', { name: 'Details', hidden: true });
    const missing = within(inspector()).getByRole('tab', { name: /^Missing/, hidden: true });
    expect(within(inspector()).getByText('Event capacity facts unavailable')).toBeInTheDocument();
    expect(inspector()).not.toHaveTextContent('PRIVATE-WITHHELD-PATH');

    details.focus();
    fireEvent.keyDown(details, { key: 'ArrowLeft' });
    expect(missing).toHaveFocus();
    expect(missing).toHaveAttribute('aria-selected', 'true');
    const loaded = within(inspector()).getByRole('region', { name: 'Loaded window missing evidence', hidden: true });
    const reports = within(inspector()).getByRole('region', { name: 'Recording reports', hidden: true });
    expect(loaded).toHaveTextContent('9007199254740993 suppressed events');
    expect(loaded).toHaveTextContent('Line events were not recorded: the line budget was exhausted.');
    expect(reports).not.toHaveTextContent('gap_event_sequence:2');
    expect(reports).toHaveTextContent('gap_event_sequence:12');
    expect(reports).toHaveTextContent('future_persisted_code');
    expect(within(reports).queryByRole('button', { name: /Go to event/ })).not.toBeInTheDocument();

    const go = within(loaded).getByRole('button', { name: 'Go to event 2' });
    const gapRow = document.querySelector<HTMLButtonElement>('#events-panel [data-step-sequence="2"] .event')!;
    expect(gapRow).toHaveTextContent('9007199254740993 events were not recorded here');
    const focus = vi.spyOn(gapRow, 'focus');
    fireEvent.click(go);
    expect(gapRow).toHaveAttribute('aria-current', 'true');
    await waitFor(() => expect(gapRow).toHaveFocus());
    expect(focus).toHaveBeenLastCalledWith({ preventScroll: true });

    // The same exact jump still focuses the row when the selection is already unchanged.
    fireEvent.click(screen.getByRole('tab', { name: 'Inspector' }));
    const sameTarget = within(inspector()).getByRole('button', { name: 'Go to event 2', hidden: true });
    sameTarget.focus();
    focus.mockClear();
    fireEvent.click(sameTarget);
    await waitFor(() => expect(gapRow).toHaveFocus());
    expect(focus).toHaveBeenLastCalledWith({ preventScroll: true });

    fireEvent.click(screen.getByRole('tab', { name: 'Inspector' }));
    const back = within(inspector()).getByRole('button', { name: /(?:Back to step · sequence 2|Focus event 2)/, hidden: true });
    back.focus();
    focus.mockClear();
    fireEvent.click(back);
    await waitFor(() => expect(gapRow).toHaveFocus());
    expect(focus).toHaveBeenLastCalledWith({ preventScroll: true });
  });
  it('shows observed zero capacity separately from a withheld adapter summary', async () => {
    responseDetail = { ...detail, capacity: { eventCap: 16, eventCount: 4, capacityDroppedEvents: '0', dropsByPriority: {} },
      adapterSummary: { Redacted: { rule_id: 'PRIVATE-RULE', shape_hint: { preview: 'PRIVATE-SUMMARY' } } } };
    await openRecording();
    const recording = within(inspector()).getByRole('region', { name: 'Recording details', hidden: true });
    expect(recording).toHaveTextContent('Capacity drops · 0');
    expect(recording).not.toHaveTextContent('Event capacity facts unavailable');
    expect(recording).toHaveTextContent('Value withheld by a redaction rule.');
    expect(recording).not.toHaveTextContent(/PRIVATE-RULE|PRIVATE-SUMMARY/);
  });
  it('offers phone replay actions and returns keyboard focus to the selected step', async () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query === '(max-width: 860px)' || query === '(max-width: 699px)', addEventListener: vi.fn(), removeEventListener: vi.fn(),
    }));
    await openRecording();
    const toolbar = screen.getByRole('group', { name: 'Replay navigation' });
    for (const name of ['Back', 'Replay', 'Next', 'More', 'Inspect']) expect(within(toolbar).getByRole('button', { name })).toBeInTheDocument();
    const more = within(toolbar).getByRole('button', { name: 'More' });
    fireEvent.click(more);
    expect(within(toolbar).getByRole('button', { name: 'Step in' })).toHaveFocus();
    fireEvent.keyDown(within(toolbar).getByRole('group', { name: 'More replay controls' }), { key: 'Escape' });
    expect(more).toHaveFocus();
    fireEvent.click(screen.getByRole('tab', { name: 'Requests' }));
    const requests = screen.getByRole('tabpanel', { name: 'Requests' });
    fireEvent.click(within(requests).getByRole('button', { name: /^Back to step · sequence 1 · / }));
    await waitFor(() => expect(document.querySelector('#events-panel .event[aria-current="true"]')).toHaveFocus());
    fireEvent.click(within(toolbar).getByRole('button', { name: 'Inspect' }));
    const back = within(inspector()).getByRole('button', { name: /Back to step · sequence 1/ });
    fireEvent.click(back);
    await waitFor(() => expect(document.querySelector('#events-panel .event[aria-current="true"]')).toHaveFocus());
  });
  it('opens the Code reading tab with explicit missing evidence on a narrow viewport', async () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query === '(max-width: 860px)', addEventListener: vi.fn(), removeEventListener: vi.fn(),
    }));
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: /Controller\.create/ }));
    const inspectorTabs = within(inspector()).getByRole('tablist', { name: 'Inspector evidence' });
    expect(within(inspectorTabs).getByRole('tab', { name: 'Code' })).toHaveAttribute('aria-selected', 'true');
    const code = within(inspector()).getByRole('region', { name: 'Code' });
    expect(within(code).getByText('Source location is unavailable for this event')).toBeInTheDocument();
    expect(within(inspector()).queryByRole('region', { name: 'Event details' })).not.toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Recording summary' })).toHaveTextContent('Event sequence 1');
  });
  it('loads opaque earlier and later pages and jumps only to an exact retained event sequence', async () => {
    const sameFrame = { ...events[2], frameId: events[1].frameId };
    const frameLess = { ...events[3], frameId: null };
    responseDetail = { ...detail, events: [events[1], sameFrame], prevCursor: 'earlier opaque+/=', nextCursor: 'later opaque+/=' };
    continuationPages.set('earlier opaque+/=', { ...detail, events: [events[0]], nextCursor: 'different edge cursor' });
    continuationPages.set('later opaque+/=', { ...detail, events: [frameLess], prevCursor: 'new preceding cursor' });
    render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: /POST \/orders/ }));
    fireEvent.click(await screen.findByRole('button', { name: new RegExp(recordingA) }));
    fireEvent.click(await screen.findByRole('button', { name: /Audit\.log/ }));
    showEvents();
    const controls = screen.getByRole('region', { name: 'Loaded event window' });
    fireEvent.click(within(controls).getByRole('button', { name: 'Load earlier' }));
    await within(controls).findByText('3 loaded events');
    expect(within(controls).getByText('Start of the available recording window.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Audit\.log/ })).toHaveAttribute('aria-current', 'true');
    fireEvent.click(within(controls).getByRole('button', { name: 'Load later' }));
    await within(controls).findByText('4 loaded events');
    expect(within(controls).getByText('No later events available from this window.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Audit\.log/ })).toHaveAttribute('aria-current', 'true');

    fireEvent.keyDown(document.body, { altKey: true, code: 'KeyJ' });
    const goPanel = screen.getByRole('dialog', { name: 'Go to step' });
    const typedSequence = within(goPanel).getByRole('textbox', { name: 'Go to step number' });
    fireEvent.change(typedSequence, { target: { value: '99' } });
    const requestCount = vi.mocked(fetch).mock.calls.length;
    fireEvent.submit(typedSequence.closest('form')!);
    expect(live()).toHaveTextContent('Event sequence is not in the loaded window.');
    expect(vi.mocked(fetch).mock.calls).toHaveLength(requestCount);
    fireEvent.change(typedSequence, { target: { value: '4' } });
    fireEvent.submit(typedSequence.closest('form')!);
    const selected = screen.getByRole('button', { name: /Audit\.write/ });
    expect(selected).toHaveAttribute('aria-current', 'true');
    await waitFor(() => expect(selected).toHaveFocus());
  });

  it('moves focus to window tools and announces when paging releases a browsed row', async () => {
    const middle = Array.from({ length: 1_999 }, (_, index) => ev(index + 2, null, `Synthetic ${index + 2}`, nav({})));
    responseDetail = { ...detail, events: [events[0]], nextCursor: 'middle-page' };
    continuationPages.set('middle-page', { ...detail, events: middle, nextCursor: 'end-page' });
    continuationPages.set('end-page', { ...detail, events: [ev(2_001, null, 'Synthetic end', nav({}))] });
    await openRecording();
    const controls = screen.getByRole('region', { name: 'Loaded event window' });
    const later = within(controls).getByRole('button', { name: 'Load later' });
    fireEvent.click(later);
    await within(controls).findByText('2000 loaded events');

    fireEvent.keyDown(document.body, { altKey: true, code: 'KeyJ' });
    const search = screen.getByRole('textbox', { name: 'Go to step number' });
    fireEvent.change(search, { target: { value: '2' } });
    fireEvent.submit(search.closest('form')!);
    const windowTools = screen.getByRole('button', { name: 'Tools' });
    const kept = screen.getByRole('button', { name: /Synthetic 2(?:\s|$)/ });
    await waitFor(() => expect(kept).toHaveFocus());
    const browsed = within(screen.getAllByRole('tabpanel', { name: 'Steps' }).find((panel) => panel.id === 'events-panel')!).getByRole('button', { name: /Controller\.create/ });
    act(() => browsed.focus());
    expect(browsed).toHaveFocus();

    fireEvent.click(later);
    await waitFor(() => expect(windowTools).toHaveFocus());
    expect(live()).toHaveTextContent('The focused event was released from the loaded window.');
    expect(browsed).not.toBeInTheDocument();
    expect(kept).toHaveAttribute('aria-current', 'true');
  });

  it('rejects a continuation response for another recording without replacing the current window', async () => {
    responseDetail = { ...detail, nextCursor: 'private opaque cursor' };
    continuationPages.set('private opaque cursor', { ...detail, recordingId: recordingB, events: [] });
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: 'Load later' }));
    const error = await screen.findByRole('alert');
    expect(error).toHaveTextContent('The local viewer could not complete this request.');
    expect(error).not.toHaveTextContent(/private opaque cursor|identity mismatch/);
    expect(screen.getByRole('button', { name: /Controller\.create/ })).toHaveAttribute('aria-current', 'true');
    expect(screen.getByRole('button', { name: 'Load later' })).toBeEnabled();
  });
  it('ignores a continuation that resolves after switching recordings', async () => {
    const token = 'old recording continuation';
    responseDetail = { ...detail, nextCursor: token };
    responseLinked = { ...linked, items: [...linked.items, { ...linked.items[0], recordingId: recordingB }] };
    let finish: ((value: Response) => void) | undefined;
    heldContinuations.set(token, new Promise<Response>((resolve) => { finish = resolve; }));
    await openRecording();
    const count = screen.getByText('4 loaded events', { exact: true });
    const loading = screen.getByText('Loading event window…', { exact: true });
    expect(count).toHaveAttribute('aria-hidden', 'false');
    expect(loading).toHaveAttribute('aria-hidden', 'true');
    expect(loading.parentElement).toBe(count.parentElement);
    fireEvent.click(screen.getByRole('button', { name: 'Load later' }));
    expect(loading).toBeInTheDocument();
    expect(loading).toHaveAttribute('aria-hidden', 'false');
    expect(count).toHaveAttribute('aria-hidden', 'true');
    expect(loading.parentElement).toBe(count.parentElement);
    secondDetail = { ...detail, recordingId: recordingB, events: [{ ...events[0], symbol: 'Other.recording' }] };
    fireEvent.click(screen.getByRole('tab', { name: 'Requests' }));
    fireEvent.click(screen.getByRole('button', { name: new RegExp(recordingB) }));
    await screen.findByRole('button', { name: /Other\.recording/ });
    await act(async () => {
      finish?.(new Response(JSON.stringify({ ...detail, events: [{ ...events[3], symbol: 'Old.continuation' }] })));
    });
    expect(screen.queryByText('Old.continuation')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Other\.recording/ })).toHaveAttribute('aria-current', 'true');
  });
});
