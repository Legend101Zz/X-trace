const timestampPattern = /^(\d{4})-(\d{2})-(\d{2})T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/i;
const millisecondsPerDay = 86_400_000;

function calendarDay(year: number, month: number, day: number): Date {
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  return date;
}

function parseTimestamp(value: string | null | undefined): Date | null {
  if (!value) return null;
  const parts = value.match(timestampPattern);
  if (!parts) return null;
  const [, year, month, day] = parts.map(Number);
  const calendar = calendarDay(year, month, day);
  // Date accepts some overflowing inputs (such as February 30) as a different date.
  if (calendar.getUTCMonth() + 1 !== month || calendar.getUTCDate() !== day) return null;
  const timestamp = new Date(value);
  return Number.isFinite(timestamp.getTime()) ? timestamp : null;
}

export function formatRecordingDates(now: Date, timeZone?: string) {
  const calendar = new Intl.DateTimeFormat('en-US-u-ca-gregory-nu-latn', {
    timeZone, year: 'numeric', month: 'numeric', day: 'numeric',
  });
  const dateLabel = new Intl.DateTimeFormat(undefined, { timeZone, dateStyle: 'medium' });
  const timeLabel = new Intl.DateTimeFormat(undefined, {
    timeZone, hour: 'numeric', minute: '2-digit', second: '2-digit', timeZoneName: 'short',
  });
  const dayKey = (timestamp: Date) => {
    const parts = new Map(calendar.formatToParts(timestamp).map(({ type, value }) => [type, Number(value)]));
    return calendarDay(parts.get('year')!, parts.get('month')!, parts.get('day')!).getTime();
  };
  const today = dayKey(now);
  return (openedAt: string | null | undefined) => {
    const timestamp = parseTimestamp(openedAt);
    if (!timestamp) return { key: null, day: 'Date unavailable', time: null };
    // Compare local calendar days on a UTC calendar, so 23- and 25-hour days remain adjacent.
    const key = dayKey(timestamp);
    const day = key === today ? 'Today' : key === today - millisecondsPerDay ? 'Yesterday' : dateLabel.format(timestamp);
    return { key, day, time: timeLabel.format(timestamp) };
  };
}
