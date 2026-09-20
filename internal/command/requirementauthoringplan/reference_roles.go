package requirementauthoringplan

// Roles classify caller observations, not authority or source authenticity.
// Admission and lazy help use this one closed vocabulary.
var referenceRoles = [...]struct {
	kind        string
	description string
}{
	{"clarification_answer", "explicit product intent or an owner answer; preserve unresolved assumptions"},
	{"code_summary", "bounded code observations; baseline and audit trust decisions remain separate"},
	{"design_doc", "design documents or external specifications used as design input, not imported authority"},
	{"implementation_plan", "implementation-plan proposals, not evidence that behavior exists"},
	{"pr_facts", "bounded pull-request observations, not merge approval"},
	{"test_summary", "test-source observations or test-coverage observations; distinguish which in summary and nonClaims"},
}

func referenceKindSet() map[string]struct{} {
	kinds := make(map[string]struct{}, len(referenceRoles))
	for _, role := range referenceRoles {
		kinds[role.kind] = struct{}{}
	}
	return kinds
}
