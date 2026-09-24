package specoverviewclaims

import "github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"

// InputPathRelation exposes the changed source-path rule without duplicating
// the requirement-source owner's filename policy.
func InputPathRelation() map[string]any {
	return map[string]any{
		"relationKind": "derived_repo_path_v1",
		"sourceField":  "specPackagePath",
		"targetField":  "requirementsPath",
		"suffix":       requirementsourceadmission.RequirementsFileSuffix,
	}
}
