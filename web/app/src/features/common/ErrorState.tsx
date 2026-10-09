export function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <div className="message error-state" role="alert"><strong>Could not load persisted evidence</strong><p>{message}</p><button className="button" onClick={onRetry}>Retry</button></div>;
}
