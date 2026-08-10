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
		return "Point supersedes only at an existing same-equivalence falsifier and cite a caller-owned supersession declaration ref, or remove the supersession declaration."
	case "missing_executable_command_ref":
		return "Add the caller-declared executable commandRef for this route, or reclassify the entry as nonsemantic evidence."
	case "missing_declared_route_anchor":
		return "Bind this test to at least one requirementRef or ownerInvariantRef, or reclassify it as helper or route-only evidence."
	case "routing_smoke_only":
		return "Treat this entry as wiring-only evidence; add a declared semantic-falsifier route when mapping is required, then bind separately admitted execution and policy evidence before assurance closure."
	case "proof_route_candidate":
		return "Review the projected proof route and bind it to an owner-authored executable oracle before materializing a declared semantic-falsifier route; the declaration still does not prove execution."
	case "incomplete_declared_oracle_metadata":
		return "Declare complete falsifier and oracle metadata that describes the intended distinction; this still does not prove execution or oracle quality."
	case "wrong_evidence_boundary":
		return "Remove requirement or invariant anchors from route-only smoke evidence, or replace it with a declared semantic-falsifier route whose oracle metadata remains explicitly caller-owned."
	default:
		return "Inspect this admitted inventory diagnostic and repair the caller-owned test inventory before using it as coverage guidance."
	}
}
