package specproofbundleadmission

import (
	"regexp"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/proofreceiptadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessschedulerplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

// Member inventories are shared by native admission and the structural projection.
var (
	inputKeys         = []string{"bundleId", "mergeRequiredReceiptIds", "nonClaims", "receiptAdmission", "receiptProducerAdmission", "requirementBindings", "schemaVersion", "witnessPlan"}
	childKeys         = []string{"exitCode", "failures", "nonClaims", "producers", "receipts", "report"}
	producerChildKeys = []string{"environmentClasses", "receiptKinds"}
	childReportKeys   = []string{"diagnostics", "nonClaims", "reportId", "reportKind", "ruleResults", "schemaVersion", "state", "summary"}
)

// Child records reuse their owners' published structures: the complete binding
// and scheduler inputs, each child's report, and its owner input operands.
func InputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	required := jsonshape.Array(id, 0).JSONSchema()
	delete(required, "$schema")
	required["uniqueItems"] = true
	properties := map[string]any{
		"bundleId": nestedSchema(id), "mergeRequiredReceiptIds": required,
		"nonClaims":                nestedSchema(jsonshape.Array(jsonshape.NonBlankString(), 0)),
		"receiptAdmission":         nullableStructure(ChildStructure(false)),
		"receiptProducerAdmission": nullableStructure(ChildStructure(true)),
		"requirementBindings":      requirementbinding.InputStructure(),
		"schemaVersion":            nestedSchema(jsonshape.IntegerLiteral(1)),
		"witnessPlan":              witnessschedulerplan.InputStructure(),
	}
	schema := closedRecord(inputKeys, properties, "receiptAdmission", "receiptProducerAdmission")
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	schema["description"] = "Six members are required; receiptAdmission and receiptProducerAdmission admit absence or explicit null as not attached. bundleId and mergeRequiredReceiptIds are exact unique RuleIDs in any order; bundle nonClaims trim to nonempty text and duplicates normalize away. requirementBindings and witnessPlan are complete child command inputs admitted by their owners. Each attached child carries its owner's exact JSON report, actual 0/1 process exit, original input operands and failures, which must be empty for a passed child. Native admission recomputes each child report and rejects owner disagreement, state/exit/failure inconsistency, RuleID privacy and timestamp exclusions and duplicate child vocabulary. Witness, binding, receipt and producer linkage failures produce admitted failed reports. Nothing executes and no repository file is read."
	return schema
}

// ChildStructure is the bundle operand for one recorded child admission.
func ChildStructure(producer bool) map[string]any {
	owner, child := proofreceiptadmission.InputStructure(), proofreceiptadmission.OutputStructure()
	producers := map[string]any{"type": "array", "items": map[string]any{"type": "object", "description": "Receipt admission ignores producer rows; any object is retained."}}
	if producer {
		owner, child = receiptproduceradmission.InputStructure(), receiptproduceradmission.OutputStructure()
		producers = owner["properties"].(map[string]any)["producers"].(map[string]any)
	}
	operands := owner["properties"].(map[string]any)
	properties := map[string]any{
		"exitCode":  nestedSchema(jsonshape.OneOf(jsonshape.IntegerLiteral(0), jsonshape.IntegerLiteral(1))),
		"failures":  map[string]any{"type": "array", "items": map[string]any{"description": "Any JSON value; only the array length is checked against the child state."}},
		"nonClaims": operands["nonClaims"], "producers": producers, "receipts": operands["receipts"], "report": child,
	}
	keys := childKeys
	if producer {
		keys = append(slices.Clone(childKeys), producerChildKeys...)
		for _, key := range producerChildKeys {
			properties[key] = operands[key]
		}
	}
	return closedRecord(keys, properties)
}

func OutputShape() jsonshape.Shape {
	return jsonshape.DiscriminatedUnion("state", reportShape(true), reportShape(false))
}

func OutputStructure() map[string]any {
	schema := OutputShape().JSONSchema()
	for _, raw := range schema["oneOf"].([]any) {
		branch := raw.(map[string]any)
		properties := branch["properties"].(map[string]any)
		properties["reportId"] = nestedSchema(jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes))
		properties["nonClaims"] = reportNonClaimsStructure()
		branch["description"] = "reportId preserves bundleId. Passed reports require passed binding and scheduler children, passed or unattached receipt children, no failures and exit 0. Failed reports carry sorted unique failures, one numbered failed rule per failure in order, and exit 1 with JSON; input refusals exit 1 on stderr without a report. receiptProducerAttached is true exactly when the producer child state is attached. nonClaims merge builtin and normalized caller claims in sorted order without deduplicating caller copies of builtin claims. Counts derive from admitted children. Structural validity does not execute witnesses, authenticate producers, compute freshness or approve merge."
	}
	return schema
}

func reportShape(passed bool) jsonshape.Shape {
	text, count := jsonshape.StringGrammar(`[\s\S]+`), jsonshape.IntegerMinimum(0)
	state, failureCount, failures := "failed", jsonshape.IntegerMinimum(1), jsonshape.Array(text, 1)
	childStates := statesShape("passed", "failed", childState(nil))
	ownerStates := statesShape("passed", "failed")
	rules := jsonshape.Array(report.RuleStructure(jsonshape.StringGrammar(regexp.QuoteMeta(failureRuleIDPrefix)+`[0-9]{3,}`),
		jsonshape.StringLiteral("failed"), text, jsonshape.Tuple()), 1)
	if passed {
		state, failureCount, failures = "passed", jsonshape.IntegerLiteral(0), jsonshape.Tuple()
		childStates, ownerStates = statesShape("passed", childState(nil)), jsonshape.StringLiteral("passed")
		rules = jsonshape.Tuple(report.RuleStructure(jsonshape.StringLiteral(acceptedRuleID), jsonshape.StringLiteral("passed"),
			jsonshape.StringLiteral(acceptedRuleMessage), jsonshape.Tuple()))
	}
	summary := jsonshape.Object(
		jsonshape.Required("bindingCommandCount", count), jsonshape.Required("bindingCount", count),
		jsonshape.Required("failureCount", failureCount), jsonshape.Required("mergeRequiredReceiptCount", count),
		jsonshape.Required("receiptCount", count), jsonshape.Required("receiptProducerAttached", jsonshape.Boolean()),
		jsonshape.Required("requirementCount", count), jsonshape.Required("witnessCommandCount", jsonshape.IntegerMinimum(1)),
	)
	children := jsonshape.Object(
		jsonshape.Required("receiptAdmissionState", childStates), jsonshape.Required("receiptProducerAdmissionState", childStates),
		jsonshape.Required("requirementBindingState", ownerStates), jsonshape.Required("witnessSchedulerState", ownerStates),
	)
	return report.Structure(1, reportKind, jsonshape.StringLiteral(state), summary,
		jsonshape.Tuple(report.DiagnosticStructure("bundleReports", children), report.DiagnosticStructure("failures", failures)), rules)
}

func reportNonClaimsStructure() map[string]any {
	claims := nestedSchema(jsonshape.Array(jsonshape.StringGrammar(`[\s\S]+`), len(boundaryNonClaims)))
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, claim := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	claims["allOf"] = contains
	return claims
}

func statesShape(values ...string) jsonshape.Shape {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return jsonshape.Enum(set)
}

// The nullable wrapper is anyOf so child-binding paths resolve the owner branch.
func nullableStructure(schema map[string]any) map[string]any {
	return map[string]any{"anyOf": []any{map[string]any{"type": "null"}, schema}}
}

// closedRecord binds a native member inventory to its complete projection.
func closedRecord(keys []string, properties map[string]any, optional ...string) map[string]any {
	if len(keys) != len(properties) {
		panic("spec proof bundle structure differs from its native member inventory")
	}
	required := []any{}
	for _, key := range slices.Sorted(slices.Values(keys)) {
		if _, member := properties[key]; !member {
			panic("spec proof bundle structure omits a native member")
		}
		if !slices.Contains(optional, key) {
			required = append(required, key)
		}
	}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
}

func nestedSchema(shape jsonshape.Shape) map[string]any {
	schema := shape.JSONSchema()
	delete(schema, "$schema")
	return schema
}
