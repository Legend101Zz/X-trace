/**
 * CV-4: Linear navigation controls. The server resolves every action (CONTRACTS 8.3);
 * the client only presents the result and never infers a tree. A control is disabled with a stated reason.
 */

export const NAV_ACTIONS = ['previous', 'next', 'into', 'over', 'out'] as const;
export type NavAction = (typeof NAV_ACTIONS)[number];

export type NavResult =
  | { state: 'target'; frameId: string }
  | { state: 'boundary'; boundaryReason?: string }
  | { state: 'unavailable'; reason?: string };

export type NavFrameNavigation = Partial<Record<NavAction, NavResult>>;

export interface NavControl {
  action: NavAction;
  label: string;
  enabled: boolean;
  /** Present exactly when the control is disabled: shown as visible text, not only a tooltip. */
  reason: string | null;
  /** Frame to move to when enabled. */
  targetFrameId: string | null;
  /** True when the target exists on the server but is not in the loaded window. */
  needsWindow: boolean;
}

const LABELS: Record<NavAction, string> = {
  previous: 'Previous frame', next: 'Next frame', into: 'Step into', over: 'Step over', out: 'Step out',
};

const UNAVAILABLE_REASONS: Record<string, string> = {
  partial_frontier: 'the recording is partial and evidence ends here',
  legacy_unindexed: 'this recording was stored before frame indexing',
  depth_overflow: 'the call depth exceeded what the recorder indexes',
  orphan_parent: 'the parent frame was not observed',
  not_navigable: 'this event is not a navigable frame',
};

const BOUNDARY_REASONS: Record<NavAction, string> = {
  previous: 'this is the first frame', next: 'this is the last frame',
  into: 'this is the last frame', over: 'no later frame at this depth', out: 'this frame is at the top level',
};

export function navigationControls(
  navigation: NavFrameNavigation | null | undefined,
  /** Frame ids present in the loaded window. */
  loadedFrameIds: ReadonlySet<string>,
): NavControl[] {
  return NAV_ACTIONS.map((action): NavControl => {
    const label = LABELS[action];
    const result = navigation?.[action];
    if (!result) return { action, label, enabled: false, reason: 'Navigation unavailable: the server did not resolve this step.', targetFrameId: null, needsWindow: false };
    if (result.state === 'target') {
      const loaded = loadedFrameIds.has(result.frameId);
      return loaded
        ? { action, label, enabled: true, reason: null, targetFrameId: result.frameId, needsWindow: false }
        : { action, label, enabled: false, reason: 'Target frame is outside the loaded window. Load the adjacent window first.', targetFrameId: result.frameId, needsWindow: true };
    }
    if (result.state === 'boundary') {
      return { action, label, enabled: false, reason: `Boundary: ${result.boundaryReason ?? BOUNDARY_REASONS[action]}.`, targetFrameId: null, needsWindow: false };
    }
    const why = result.reason ? (UNAVAILABLE_REASONS[result.reason] ?? result.reason.replaceAll('_', ' ')) : 'no reason was reported';
    return { action, label, enabled: false, reason: `Unavailable: ${why}.`, targetFrameId: null, needsWindow: false };
  });
}
