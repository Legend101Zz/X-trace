import './values.css';

export function WhyDisclosure({ lines, label }: { lines: readonly string[]; label?: string }) {
  return <details className="value-why">
    <summary aria-label={label ? `Why? ${label}` : undefined}>Why?</summary>
    {lines.map((line, index) => <p key={index}>{line}</p>)}
  </details>;
}
