package testevidenceinventory

import (
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const agentActionNonClaim = "Agent action plan is deterministic guidance over admitted caller-owned inventory only; consumers own test edits, native execution, merge policy, and semantic truth."

func agentActionPlan(failures []string, warnings []string) []map[string]any {
	actions := make([]map[string]any, 0, len(failures)+len(warnings))
	for _, diagnostic := range failures {
		actions = append(actions, agentAction(diagnostic, "failure"))
	}
	for _, diagnostic := range warnings {
		actions = append(actions, agentAction(diagnostic, "warning"))
	}
	sort.Slice(actions, func(left, right int) bool {
		leftKey := actions[left]["severity"].(string) + "\x00" + actions[left]["classificationId"].(string) + "\x00" + actions[left]["diagnostic"].(string)
		rightKey := actions[right]["severity"].(string) + "\x00" + actions[right]["classificationId"].(string) + "\x00" + actions[right]["diagnostic"].(string)
		return leftKey < rightKey
	})
	return actions
}

func agentAction(diagnostic string, severity string) map[string]any {
	classificationID := diagnosticClassID(diagnostic)
	return map[string]any{
		"actionId":         "proofkit.test-inventory." + classificationID,
		"classificationId": classificationID,
		"decisionOwner":    "consumer_repository",
		"diagnostic":       diagnostic,
		"evidenceRefs":     admit.StringSliceToAny([]string{diagnostic}),
		"instruction":      instructionForDiagnostic(diagnostic, classificationID),
		"nonClaim":         agentActionNonClaim,
		"severity":         severity,
	}
}

func instructionForDiagnostic(diagnostic string, classificationID string) string {
	if strings.HasPrefix(diagnostic, "quality_finding:") {
		return "Review the caller-declared quality finding, fix the test or contract when confirmed, and keep severity owned by the consumer repository."
	}
	switch classificationID {
	case "declared_duplicate_falsifier":
		return "Keep one active falsifier per equivalence class, or use same-equivalence supersession to retire the older falsifier explicitly."
	case "invalid_falsifier_supersession":
		return "Point supersedes only at an existing same-equivalence falsifier and cite a dominance proof ref, or remove the supersession claim."
	case "missing_executable_command_ref":
		return "Add the executable commandRef that runs this semantic falsifier, or reclassify the entry as nonsemantic evidence."
	case "missing_semantic_anchor":
		return "Bind this test to at least one requirementRef or ownerInvariantRef, or reclassify it as helper or route-only evidence."
	case "routing_smoke_only":
		return "Treat this entry as wiring-only evidence; add a separate semantic_falsifier entry if a requirement or command must be satisfied."
	case "weak_or_empty_oracle":
		return "Declare a falsifier and a non-empty assertion oracle that distinguishes the intended failure from the implementation under test."
	case "wrong_evidence_boundary":
		return "Remove semantic anchors from route-only smoke evidence, or replace it with a semantic_falsifier entry that carries a real oracle."
	default:
		return "Inspect this admitted inventory diagnostic and repair the caller-owned test inventory before using it as coverage guidance."
	}
}
