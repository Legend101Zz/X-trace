/// <reference types="vite/client" />
// Automated accessibility checks (no axe in the pinned toolset, so these are explicit structural
// rules over the rendered DOM): accessible names, unique ids, valid references, roving tabindex,
// landmarks, hidden decoration, and the keyboard-only focus order. They do not replace a manual
// screen-reader pass (UX-ACCESSIBILITY stays partial until the owner does one).
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './main';

const operationA = '018f0000-0000-7000-8000-000000000001';
const recordingA = '018f0000-0000-7000-8000-000000000011';
const endpoints = { items: [{ operationId: operationA, projectId: 'p', applicationComponent: 'svc', binding: 'default', method: 'POST', routeTemplate: '/orders', observation: 'observed', observationPolicy: 'pol' }], nextCursor: null };
const linked = { items: [{ recordingId: recordingA, status: 'complete', completion: 'complete', openedAt: '2026-10-03T10:00:00Z', segmentCount: '1', eventCount: '3', firstSequence: '1', lastSequence: '3', incompleteEvidence: [], operationId: operationA, observationPolicy: 'pol', unmatchedReason: null }], nextCursor: null };
const none = { state: 'boundary' };
const ev = (n: number, parent: string | null, symbol: string) => ({ sequence: String(n), frameId: `f${n}`, eventId: `event-${n}`, navigation: { previous: none, next: none, into: none, over: none, out: none }, monotonicNs: String(n * 10), kind: 'method', symbol, parentFrameId: parent, sourceBinding: 'unspecified', fieldTruncations: [] });
const detail = {
  recordingId: recordingA, status: 'complete', completion: 'complete', adapterSummary: null, durationNs: '20', dropCountsByPriority: {}, segmentCount: '1', incompleteEvidence: [], nextCursor: null,
  unavailable: { source: 'unavailable', values: 'unavailable', completion: 'unavailable' }, outcome: null,
  events: [ev(1, null, 'Controller.create'), ev(2, 'f1', 'Repo.save'), ev(3, 'f1', 'Audit.log')],
};
const json = (body: unknown) => Promise.resolve(new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } }));

function accessibleName(element: Element): string {
  const label = element.getAttribute('aria-label');
  if (label?.trim()) return label.trim();
  const by = element.getAttribute('aria-labelledby');
  if (by) return by.split(/\s+/).map((id) => document.getElementById(id)?.textContent ?? '').join(' ').trim();
  return (element.textContent ?? '').trim();
}

/** Returns a list of human-readable violations; an empty list is a pass. */
function audit(): string[] {
  const problems: string[] = [];
  for (const element of document.querySelectorAll('button, [role="tab"], [role="treeitem"], a[href], input, select, textarea')) {
    if (!accessibleName(element)) problems.push(`no accessible name: <${element.tagName.toLowerCase()} class="${element.className}">`);
  }
  const ids = Array.from(document.querySelectorAll('[id]')).map((element) => element.id);
  for (const id of new Set(ids.filter((id, index) => ids.indexOf(id) !== index))) problems.push(`duplicate id ${id}`);
  for (const attribute of ['aria-controls', 'aria-labelledby', 'aria-describedby']) {
    for (const element of document.querySelectorAll(`[${attribute}]`)) {
      for (const id of (element.getAttribute(attribute) ?? '').split(/\s+/).filter(Boolean)) {
        if (!document.getElementById(id)) problems.push(`${attribute} points at missing id ${id}`);
      }
    }
  }
  for (const element of document.querySelectorAll('[tabindex]')) {
    if (Number(element.getAttribute('tabindex')) > 0) problems.push('positive tabindex');
  }
  if (document.querySelectorAll('main').length !== 1) problems.push('expected exactly one main landmark');
  if (document.querySelectorAll('header').length !== 1) problems.push('expected exactly one banner');
  if (!document.querySelector('nav[aria-label]')) problems.push('navigation landmark needs a label');
  if (!document.querySelector('[aria-live="polite"][role="status"]')) problems.push('no polite live region');
  for (const svg of document.querySelectorAll('svg')) {
    if (svg.getAttribute('aria-hidden') !== 'true' && !svg.querySelector('title')) problems.push('svg is neither hidden nor titled');
  }
  const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
  if (tabs.filter((tab) => tab.getAttribute('tabindex') === '0').length !== 1) problems.push('tablist must have exactly one tab stop');
  if (document.querySelector('[role="tree"]')) {
    const stops = Array.from(document.querySelectorAll('[role="treeitem"]')).filter((item) => item.getAttribute('tabindex') === '0');
    if (stops.length !== 1) problems.push(`tree must have exactly one tab stop, found ${stops.length}`);
    for (const item of document.querySelectorAll('[role="treeitem"]')) {
      if (!item.getAttribute('aria-level')) problems.push('treeitem without aria-level');
    }
  }
  for (const group of document.querySelectorAll('[role="group"]')) {
    if (!accessibleName(group)) problems.push('group without a name');
  }
  return problems;
}

async function openRecording() {
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: /POST \/orders/ }));
  fireEvent.click(await screen.findByRole('button', { name: new RegExp(recordingA) }));
  await screen.findByText('Controller.create');
  fireEvent.click(screen.getByRole('tab', { name: 'events' }));
}

describe('accessibility rules over the rendered viewer', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/viewer#token=t');
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = new URL(String(input), window.location.origin).pathname + new URL(String(input), window.location.origin).search;
      if (path === '/api/v1/auth/exchange') return json({ authenticated: true });
      if (path.startsWith('/api/v1/endpoints?')) return json(endpoints);
      if (path.includes('/recordings') && path.includes('/endpoints/')) return json(linked);
      if (path.startsWith('/api/v1/recordings/')) return json(detail);
      throw new Error(`Unexpected request ${path}`);
    }));
  });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

  it('has no structural violations in the Linear view', async () => {
    await openRecording();
    expect(audit()).toEqual([]);
  });

  it('has no structural violations in the Canvas view', async () => {
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: 'Canvas' }));
    expect(screen.getByRole('tree')).toBeInTheDocument();
    expect(audit()).toEqual([]);
  });

  it('the audit itself catches a nameless button and a duplicate id', () => {
    document.body.innerHTML = '<main><button></button><div id="a"></div><div id="a"></div></main>';
    const problems = audit();
    expect(problems.some((problem) => problem.startsWith('no accessible name'))).toBe(true);
    expect(problems).toContain('duplicate id a');
    document.body.innerHTML = '';
  });

  it('keyboard-only: Tab visits the active tab, then controls in DOM order, with one tree stop', async () => {
    const user = userEvent.setup();
    await openRecording();
    fireEvent.click(screen.getByRole('button', { name: 'Canvas' }));
    (document.activeElement as HTMLElement | null)?.blur();
    const order: string[] = [];
    for (let step = 0; step < 60; step += 1) {
      await user.tab();
      const active = document.activeElement as HTMLElement;
      const role = active.getAttribute('role') ?? active.tagName.toLowerCase();
      order.push(`${role}:${accessibleName(active).slice(0, 40)}`);
      if (active === document.body) break;
    }
    // The first stop is the single active tab, never an inactive one.
    expect(order[0]).toBe('tab:events');
    expect(order.filter((entry) => entry.startsWith('treeitem:'))).toHaveLength(1);
    // Expand buttons inside the tree are reachable by pointer, not by Tab (roving tabindex).
    expect(order.some((entry) => entry.startsWith('button:Expand') || entry.startsWith('button:Collapse'))).toBe(false);
    // The tree stop comes after the Linear/Canvas switch.
    const canvasIndex = order.indexOf('button:Canvas');
    const treeIndex = order.findIndex((entry) => entry.startsWith('treeitem:'));
    expect(canvasIndex).toBeGreaterThan(-1);
    expect(treeIndex).toBeGreaterThan(canvasIndex);
  });
});
