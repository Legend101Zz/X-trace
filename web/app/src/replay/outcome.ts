/** OUT-4: outcome banner text. Everything here is adapter-observed or absent; nothing is inferred. */

/** Shape of `RecordingDetail.outcome` (CONTRACTS 5/7.1). Adapter-observed; null when terminal evidence is absent. */
export interface OutcomeView {
  kind: 'responded' | 'exception' | 'unobserved';
  httpStatus: number | null;
  exception: { exceptionType: string; message: string | null } | null;
  thrownFromEventId?: string | null;
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
  if (!/^\d+$/.test(ns)) return 'unavailable';
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
  if (!outcome) lines.push('Outcome unavailable: no terminal evidence was recorded');
  else {
    if (outcome.httpStatus != null) lines.push(`Response status ${outcome.httpStatus} (as reported by the adapter)`);
    else if (outcome.kind === 'unobserved') lines.push('Response status was not observed');
    else lines.push('Response status was not reported');
    if (outcome.kind === 'unobserved') lines.push('Outcome was not observed by the adapter');
    if (outcome.exception) {
      const { exceptionType, message } = outcome.exception;
      lines.push(message == null ? `Exception ${exceptionType}: message not recorded` : `Exception ${exceptionType}: ${message}`);
    } else if (outcome.kind === 'exception') lines.push('Exception reported without details');
  }
  lines.push(input.durationNs != null ? `Adapter-observed duration ${nsToLabel(input.durationNs)} (measured by the adapter, not verified by X-trace)` : 'Duration unavailable for this capture');
  for (const reason of input.incompleteEvidence) lines.push(`Persisted incomplete evidence: ${reason}`);
  return { tone, headline: COMPLETION_HEADLINE[tone], lines };
}
