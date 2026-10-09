/**
 * SRC-4: one distinct, honest sentence per source-binding state. Strings follow CONTRACTS 7.3 and are
 * replaced by schema/fixtures/replay/honesty-strings.json once C ships it; keep keys, not wording, stable.
 */

export interface SourceInput {
  status: string;
}

export function sourceStateText(binding: string | undefined, source: SourceInput | null | undefined): string {
  if (source) {
    switch (source.status) {
      case 'matched':
        if (binding === 'observed_unattested') return 'Source as read when the class loaded; the current file matches the recorded hash. No build attestation backs this.';
        return 'Adapter reported a compile-time source binding; current source matches the recorded identity · verified build attestation';
      case 'mismatch':
        return 'Adapter reported a compile-time source binding; current source differs from the recorded identity · source changed since recording';
      case 'missing_file':
        return 'Source file missing: the recorded path is no longer present, so no source is shown.';
      default:
        return 'Current source could not be verified safely';
    }
  }
  switch (binding) {
    case 'attestation_missing': return 'Build source attestation was absent';
    case 'class_bytes_mismatch': return 'Loaded class bytes did not match the adapter-reported build attestation';
    case 'debug_metadata_absent': return 'Compiled method line metadata was absent';
    case 'source_metadata_invalid': return 'Build source metadata was invalid';
    case 'observed_unattested': return 'Source location was observed when the class loaded but is not attested; no source is shown.';
    case 'source_map_absent': return 'Source map absent: this is a generated path, so no original source is shown.';
    case 'source_map_unresolved': return 'Source map did not resolve to an original file, so no source is shown.';
    default: return 'Source location is unavailable for this event';
  }
}
