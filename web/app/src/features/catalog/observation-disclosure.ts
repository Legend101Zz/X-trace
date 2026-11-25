const unmatchedLabels = {
  observation_policy_missing: 'Observation policy was not recorded.',
  observation_policy_invalid: 'Observation policy could not be accepted.',
  identity_context_missing: 'Application or binding context was not recorded.',
  identity_context_invalid: 'Application or binding context could not be accepted.',
  method_unsupported: 'The recorded method is unsupported by the observation policy.',
  route_unapproved: 'The observation policy did not approve the route.',
  catalog_revision_unavailable: 'The catalog revision was unavailable.',
  route_template_unavailable_or_ineligible: 'A route template eligible for catalog linking was unavailable.',
  no_catalog_match: 'No eligible operation matched the recorded catalog context.',
} as const;

// Unexpected input is never echoed, including values from newer readers or malformed responses.
export function unmatchedReasonLabel(reason: string | null | undefined): string {
  if (!reason) return 'No historical reason recorded';
  return Object.hasOwn(unmatchedLabels, reason)
    ? unmatchedLabels[reason as keyof typeof unmatchedLabels]
    : 'The recorded reason is unavailable in this viewer.';
}

export function observationPolicyLabel(policy: string | null | undefined): string | null {
  return policy === 'spring-orders-v1' || policy === 'runtime-route-v1' ? policy : null;
}
