package requirementsourcemodel

// Reference closure precedes this check. Text equality does not imply shared
// ownership; it is a duplicate only inside one effective boundary scope.
func validateNonClaimScopes(source []string, sourceRefs []string, definitions []NonClaimDefinition, requirements []AtomicRequirement) error {
	statements := make(map[string]string, len(definitions))
	for _, definition := range definitions {
		statements[definition.NonClaimID] = definition.Statement
	}
	if err := validateNonClaimScope(source, sourceRefs, statements, "sourceNonClaimRefs"); err != nil {
		return err
	}
	for _, requirement := range requirements {
		if err := validateNonClaimScope(requirement.NonClaims, requirement.NonClaimRefs, statements, identified("requirements", requirement.RequirementID)+".nonClaimRefs"); err != nil {
			return err
		}
	}
	return nil
}

func validateNonClaimScope(direct []string, refs []string, statements map[string]string, refsPath string) error {
	seen := make(map[string]struct{}, len(direct)+len(refs))
	for _, statement := range direct {
		seen[statement] = struct{}{}
	}
	for _, ref := range refs {
		statement := statements[ref]
		if _, exists := seen[statement]; exists {
			return invalid("duplicate_effective_nonclaim", refsPath)
		}
		seen[statement] = struct{}{}
	}
	return nil
}
