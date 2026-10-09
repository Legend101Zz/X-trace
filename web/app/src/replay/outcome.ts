/** OUT-4: outcome banner text. Everything here is adapter-observed or absent; nothing is inferred. */

export interface OutcomeView {
  kind?: string | null;
  httpStatus?: number | null;
  exception?: { type?: string | null; message?: { state: string } | null } | null;
}

export interface OutcomeBannerModel {
  tone: 'complete' | 'partial' | 'invalid' | 'unavailable';
  headline: string;
  lines: string[];
}

const COMPLETION_HEADLINE: Record<OutcomeBannerModel['tone'], string> = {
  complete: 'Recording complete: finish evidence was verified.',
  partial: 'Recording partial: some evidence is missing.',
  invalid: 'Recording invalid: stored evidence failed verification.',
  unavailable: 'Completion unavailable for this recording.',
};

function nsToLabel(ns: string): string {
  const value = BigInt(ns);
  if (value < 1_000_000n) return `${value} ns`;
  const tenths = value / 100_000n;
  return `${tenths / 10n}.${tenths % 10n} ms`;
}

export function outcomeBanner(input: {
  completion: string;
  incompleteEvidence: readonly string[];
  durationNs: string | null;
  outcome?: OutcomeView | null;
}): OutcomeBannerModel {
  const tone = (['complete', 'partial', 'invalid'] as const).find((value) => value === input.completion) ?? 'unavailable';
  const lines: string[] = [];
  const { outcome } = input;
  if (outcome?.httpStatus != null) lines.push(`Response status ${outcome.httpStatus} (as reported by the adapter)`);
  else lines.push('Response status was not observed');
  if (outcome?.exception) {
    const type = outcome.exception.type ? ` ${outcome.exception.type}` : '';
    const state = outcome.exception.message?.state;
    lines.push(state === 'redacted' ? `Exception${type}: message redacted` : state === 'unavailable' ? `Exception${type}: message unavailable` : `Exception${type} observed`);
  }
  lines.push(input.durationNs != null ? `Adapter-observed duration ${nsToLabel(input.durationNs)} (measured by the adapter, not verified by X-trace)` : 'Duration unavailable for this capture');
  for (const reason of input.incompleteEvidence) lines.push(`Persisted incomplete evidence: ${reason}`);
  return { tone, headline: COMPLETION_HEADLINE[tone], lines };
}
