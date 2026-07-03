package requirementcoverageview

import (
	"sort"
	"strings"
)

func diagnosticClassifications(diagnostics []string, severity string) []map[string]any {
	result := make([]map[string]any, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, map[string]any{
			"classificationId": diagnosticClassID(diagnostic),
			"diagnostic":       diagnostic,
			"severity":         severity,
		})
	}
	sort.Slice(result, func(left, right int) bool {
		leftKey := stringValue(result[left]["classificationId"]) + "\x00" + stringValue(result[left]["diagnostic"])
		rightKey := stringValue(result[right]["classificationId"]) + "\x00" + stringValue(result[right]["diagnostic"])
		return leftKey < rightKey
	})
	return result
}

func diagnosticClassID(diagnostic string) string {
	switch {
	case strings.HasPrefix(diagnostic, "dead_zone:") || strings.HasPrefix(diagnostic, "dead_zone_advisory:"):
		return "declared_dead_zone"
	case strings.HasPrefix(diagnostic, "missing_proof_binding_route:") || strings.HasPrefix(diagnostic, "proof_binding_unknown_requirement:"):
		return "missing_requirement_binding"
	case strings.HasPrefix(diagnostic, "missing_test_inventory:") || strings.HasPrefix(diagnostic, "missing_command_semantic_falsifier:"):
		return "missing_semantic_test"
	case strings.HasPrefix(diagnostic, "missing_owner_invariant_inventory:"):
		return "missing_semantic_test"
	case strings.HasPrefix(diagnostic, "nonsemantic_command_evidence:"):
		return "nonsemantic_command_evidence"
	case strings.HasPrefix(diagnostic, "route_only_nonclaim:") ||
		strings.HasPrefix(diagnostic, "command_route_only_nonclaim:") ||
		strings.HasPrefix(diagnostic, "covered_by_routing_smoke_nonclaim:"):
		return "routing_smoke_only"
	case strings.HasPrefix(diagnostic, "unknown_requirement_ref:") ||
		strings.HasPrefix(diagnostic, "unknown_owner_invariant_ref:") ||
		strings.HasPrefix(diagnostic, "unknown_command_or_witness_ref:"):
		return "unknown_reference"
	case strings.HasPrefix(diagnostic, "full_repository_source_requirement_outside_owner_scope:") ||
		strings.HasPrefix(diagnostic, "inventory_entry_owner_outside_scope:"):
		return "owner_scope_violation"
	case strings.HasPrefix(diagnostic, "test_inventory_failed:"):
		return "failed_test_inventory"
	case strings.HasPrefix(diagnostic, "covered_by_governance_invariant_nonproduct:"):
		return "nonsemantic_governance_evidence"
	case strings.HasPrefix(diagnostic, "not_applicable:"):
		return "not_applicable_with_reason"
	default:
		return "unclassified_gap"
	}
}
