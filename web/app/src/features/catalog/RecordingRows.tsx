import { Fragment } from 'react';
import type { Recording } from '../../types';
import { formatRecordingDates } from './recording-dates';
import { useViewerPreferences } from '../shell/viewer-preferences';
import './recording-rows.css';

export function RecordingRows({ items, selected, arrivals, onSelect }: { items: Recording[]; selected: string; arrivals: ReadonlySet<string>; onSelect: (id: string) => void }) {
  const { time } = useViewerPreferences();
  const formatDate = formatRecordingDates(new Date(), time === 'utc' ? 'UTC' : undefined);
  const rows = items.map((recording) => ({ recording, date: formatDate(recording.openedAt) }));
  return <div className="recording-list">{rows.map(({ recording, date }, index) => <Fragment key={recording.recordingId}>
    {rows[index - 1]?.date.key !== date.key ? <h2 className="recording-date-heading">{date.day}</h2> : null}
    <button className="recording" aria-current={selected === recording.recordingId} onClick={() => onSelect(recording.recordingId)}>
      <span className={`status-mark status-mark--${recording.status}`} aria-hidden="true" />
      <span><span className="recording-title">{recording.recordingId}</span><span className="recording-sub">{recording.eventCount} persisted events · {date.time === null ? 'Time unavailable' : <time dateTime={recording.openedAt}>{date.time}</time>}</span><span className="recording-status">{recording.status}</span>{arrivals.has(recording.recordingId) ? <span className="recording-arrival">New to this list</span> : null}{recording.unmatchedReason ? <span className="recording-reason">{recording.unmatchedReason}</span> : recording.operationId === null ? <span className="recording-reason">No historical reason recorded</span> : null}</span>
    </button>
  </Fragment>)}</div>;
}
