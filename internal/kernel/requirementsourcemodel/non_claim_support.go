package requirementsourcemodel

import "slices"

// NormalizeNonClaimDefinitions admits a bounded detached support set using the
// same identities and statements as whole-source admission.
func NormalizeNonClaimDefinitions(values []NonClaimDefinition) ([]NonClaimDefinition, error) {
	limits := DefaultLimits()
	if len(values) > limits.MaxDefinitions {
		return nil, invalid("definition_budget_exceeded", "nonClaimDefinitions")
	}
	var size uint64
	for _, value := range values {
		size += textBytes(value.NonClaimID, value.Statement)
		if size > uint64(limits.MaxTotalTextBytes) {
			return nil, invalid("text_budget_exceeded", "nonClaimDefinitions")
		}
	}
	definitions, _, err := normalizeDefinitions(values)
	return definitions, err
}

// ValidateResolvedNonClaimScope checks one source-local scope against an index
// made from admitted definitions. The index does not resolve external refs.
func ValidateResolvedNonClaimScope(direct, refs []string, statements map[string]string) error {
	canonicalDirect, err := normalizeTexts(direct, "nonClaims", true, false)
	if err != nil {
		return err
	}
	canonicalRefs, err := normalizeIDs(refs, "NCL-", "nonClaimRefs", true)
	if err != nil {
		return err
	}
	if !slices.Equal(canonicalDirect, direct) || !slices.Equal(canonicalRefs, refs) {
		return invalid("noncanonical_nonclaim_scope", "nonClaimRefs")
	}
	for _, ref := range refs {
		if _, exists := statements[ref]; !exists {
			return invalid("dangling_nonclaim_ref", "nonClaimRefs")
		}
	}
	return validateNonClaimScope(direct, refs, statements, "nonClaimRefs")
}
