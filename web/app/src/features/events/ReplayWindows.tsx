export function ReplayWindows({ prevCursor, nextCursor, count, busy, startKnown, released, onChange }: {
  prevCursor: string | null;
  nextCursor: string | null;
  count: number;
  busy: boolean;
  startKnown: boolean;
  released: 'earlier' | 'later' | null;
  onChange: (direction: 'earlier' | 'later') => void;
}) {
  return <section className="replay-windows" aria-label="Loaded event window">
    <p className="replay-window-count">
      <span aria-hidden={busy}>{count} loaded {count === 1 ? 'event' : 'events'}</span>
      <span aria-hidden={!busy}>Loading event window…</span>
    </p>
    <div className="replay-window-actions">
      {prevCursor ? <button className="button" type="button" disabled={busy} onClick={() => onChange('earlier')}>Load earlier</button>
        : <p>{startKnown ? 'Start of the available recording window.' : 'Earlier events are unavailable from this window.'}</p>}
      {nextCursor ? <button className="button" type="button" disabled={busy} onClick={() => onChange('later')}>Load later</button>
        : <p>No later events available from this window.</p>}
    </div>
    {released ? <p>{released === 'earlier' ? 'Earlier' : 'Later'} events were released from memory.</p> : null}
  </section>;
}
