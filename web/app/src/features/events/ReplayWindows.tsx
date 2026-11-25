import { useState } from 'react';

export function ReplayWindows({ prevCursor, nextCursor, count, busy, startKnown, released, onChange, onJump }: {
  prevCursor: string | null;
  nextCursor: string | null;
  count: number;
  busy: boolean;
  startKnown: boolean;
  released: 'earlier' | 'later' | null;
  onChange: (direction: 'earlier' | 'later') => void;
  onJump: (sequence: string) => void;
}) {
  const [sequence, setSequence] = useState('');
  return <section className="replay-windows" aria-label="Loaded event window">
    <p className="replay-window-count">{count} loaded {count === 1 ? 'event' : 'events'}</p>
    <div className="replay-window-actions">
      {prevCursor ? <button className="button" type="button" disabled={busy} onClick={() => onChange('earlier')}>Load earlier</button>
        : <p>{startKnown ? 'Start of the available recording window.' : 'Earlier events are unavailable from this window.'}</p>}
      {nextCursor ? <button className="button" type="button" disabled={busy} onClick={() => onChange('later')}>Load later</button>
        : <p>No later events available from this window.</p>}
    </div>
    {busy ? <p>Loading event window…</p> : null}
    {released ? <p>{released === 'earlier' ? 'Earlier' : 'Later'} events were released from memory.</p> : null}
    {count ? <form className="replay-window-search" onSubmit={(event) => {
      event.preventDefault();
      if (/^\d+$/.test(sequence.trim())) onJump(sequence.trim());
    }}>
      <label htmlFor="jump-event-sequence" id="jump-event-sequence-label">Loaded event sequence</label>
      <input type="text" id="jump-event-sequence" aria-labelledby="jump-event-sequence-label" inputMode="numeric"
        pattern="[0-9]+" required value={sequence} onChange={(event) => setSequence(event.currentTarget.value)} />
      <button className="button" type="submit" disabled={busy}>Go to event</button>
    </form> : null}
  </section>;
}
