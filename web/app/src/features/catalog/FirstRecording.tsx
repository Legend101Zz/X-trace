import { useState } from 'react';
import { StartTourButton } from '../shell/ViewerTour';

const command = 'xtrace run --project-dir ./your-project --java-agent ./xtrace-java-agent.jar -- java -jar ./your-app.jar';

export function FirstRecording({ onAnnounce }: { onAnnounce: (message: string) => void }) {
  const [feedback, setFeedback] = useState('');
  async function copy() {
    let result: string;
    try {
      await navigator.clipboard.writeText(command);
      result = 'Example command copied.';
    } catch {
      result = 'Select and copy the example command manually.';
    }
    setFeedback(result);
    onAnnounce(result);
  }

  return <section className="first-recording" aria-labelledby="first-recording-title">
    <h2 id="first-recording-title">No recordings yet</h2>
    <p>Start a supported Java application with X-trace, send it a request, then refresh Requests.</p>
    <div className="first-recording-command">
      <p>Replace the example paths with your initialized project, built Java agent and application JAR.</p>
      <code>{command}</code>
      <button type="button" className="button" onClick={() => void copy()}>Copy example command</button>
      {feedback ? <p>{feedback}</p> : null}
    </div>
    <StartTourButton />
  </section>;
}
