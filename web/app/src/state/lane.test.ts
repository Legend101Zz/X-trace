import { describe, expect, it } from 'vitest';
import { Lane } from './lane';

describe('request lane', () => {
  it('stale_reply_does_not_overwrite_newer_selection: a later begin supersedes and aborts the earlier request', () => {
    const lane = new Lane();
    const first = lane.begin();
    const second = lane.begin();
    expect(first.signal.aborted).toBe(true);
    expect(second.signal.aborted).toBe(false);
    expect(lane.isCurrent(first.generation)).toBe(false);
    expect(lane.isCurrent(second.generation)).toBe(true);
  });

  it('invalidate supersedes the in-flight request without starting another', () => {
    const lane = new Lane();
    const request = lane.begin();
    lane.invalidate();
    expect(request.signal.aborted).toBe(true);
    expect(lane.isCurrent(request.generation)).toBe(false);
  });
});
