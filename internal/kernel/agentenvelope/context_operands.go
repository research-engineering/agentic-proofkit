package agentenvelope

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
)

// ContextReferenceField declares a producer-owned structural reference field.
// Only canonical repository paths can also authorize an argv path binding.
type ContextReferenceField struct {
	ContextRefID string
	Field        string
}

type contextOperandKey struct{ refID, field string }

func admitContextOperands(contexts []map[string]any, fields []ContextReferenceField, rejected map[string]struct{}) ([]map[string]any, map[contextOperandKey]admittedStructuralOperand, int) {
	declared := map[string]map[string]int{}
	for _, field := range fields {
		if declared[field.ContextRefID] == nil {
			declared[field.ContextRefID] = map[string]int{}
		}
		declared[field.ContextRefID][field.Field]++
	}
	paths := map[contextOperandKey]admittedStructuralOperand{}
	result := make([]map[string]any, 0, len(contexts))
	omitted := 0
	for _, context := range contexts {
		id := context["refId"].(string)
		requested := declared[id]
		delete(declared, id)
		modes := map[string]bool{}
		if _, exists := context["ref"]; exists {
			modes["ref"] = false
		}
		valid := true
		for field, count := range requested {
			if field == "" || field == "refId" || count != 1 {
				valid = false
			}
			modes[field] = true
		}
		values := map[string]admittedStructuralOperand{}
		localPaths := map[contextOperandKey]admittedStructuralOperand{}
		for field, explicit := range modes {
			text, ok := context[field].(string)
			if !ok || !unicodepolicy.ValidScalarString(text) || unicodepolicy.ContainsUnsafeScalar(text) {
				valid = false
				continue
			}
			pathRole := explicit || (field == "ref" && context["kind"] == "path")
			canonical, err := admit.SafeRepoRelativePath(text, "agent envelope context path")
			if pathRole && (err == nil || text == ".") {
				if text == "." {
					canonical = text
				}
				operand := admittedStructuralOperand(canonical)
				values[field] = operand
				localPaths[contextOperandKey{id, field}] = operand
			} else if admit.RedactStructuralText(text) == text {
				values[field] = admittedStructuralOperand(text)
			} else {
				valid = false
			}
		}
		if !valid {
			rejected[id] = struct{}{}
			omitted++
			continue
		}
		// Commit all fields together: a rejected sibling must not authorize argv.
		for field, value := range values {
			context[field] = value
		}
		for key, value := range localPaths {
			paths[key] = value
		}
		result = append(result, context)
	}
	for _, unmatched := range declared {
		for _, count := range unmatched {
			omitted += count
		}
	}
	return result, paths, omitted
}
