import { createContext, useContext, useId, useLayoutEffect, useRef } from 'react';
import type { Pane } from '../../types';

const steps = [
  {
    pane: 'recordings',
    title: 'Find a recording',
    description: 'Open an observed endpoint to see its linked recordings, or look under Not linked to an endpoint.',
  },
  {
    pane: 'events',
    title: 'Read Steps in order',
    description: 'Choose a recording, then use Steps to read each recorded event. Back and Next move between loaded events.',
  },
  {
    pane: 'evidence',
    title: 'Check what was recorded',
    description: 'Open Missing in the Inspector to see gaps and limitations reported by the recording. A gap leaves execution unknown.',
  },
] as const satisfies readonly { pane: Pane; title: string; description: string }[];

export const tourPanes = steps.map(({ pane }) => pane);
export const TourLauncher = createContext<(button: HTMLButtonElement) => void>(() => undefined);

export function StartTourButton() {
  const start = useContext(TourLauncher);
  return <button type="button" className="button" onClick={(event) => start(event.currentTarget)}>Take the 3-step tour</button>;
}

export function ViewerTour({ index, selectedRecording, onStep, onClose }: {
  index: number;
  selectedRecording: boolean;
  onStep: (index: number) => void;
  onClose: () => void;
}) {
  const title = useRef<HTMLHeadingElement>(null);
  const prefix = useId();
  useLayoutEffect(() => { title.current?.focus({ preventScroll: true }); }, [index]);

  const step = steps[index];
  const final = index === steps.length - 1;
  return <section className={`viewer-tour viewer-tour--${step.pane}`} role="dialog" aria-modal="false"
    aria-labelledby={`${prefix}-title`} aria-describedby={`${prefix}-position ${prefix}-text`}>
    <p id={`${prefix}-position`}>Step {index + 1} of {steps.length}</p>
    <h2 id={`${prefix}-title`} ref={title} tabIndex={-1}>{step.title}</h2>
    <p id={`${prefix}-text`}>{step.description}</p>
    {!selectedRecording && index > 0 ? <p>Select a recording to see its events and evidence.</p> : null}
    <div className="viewer-tour-actions">
      <button type="button" className="button" onClick={onClose}>Skip tour</button>
      {index > 0 ? <button type="button" className="button" onClick={() => onStep(index - 1)}>Previous</button> : null}
      <button type="button" className="button button-primary" onClick={final ? onClose : () => onStep(index + 1)}>
        {final ? 'Finish' : 'Next'}
      </button>
    </div>
  </section>;
}
