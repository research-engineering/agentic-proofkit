package adoptionchecklist

import (
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputKeys = []string{"checklistId", "items", "nextCommandRefs", "nonClaims", "requiredItemIds", "scenario", "schemaVersion"}
var itemKeys = []string{"blocker", "commandRefs", "evidenceRefs", "itemId", "label", "nonClaims", "owner", "status"}

func itemFields() map[string]jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return map[string]jsonshape.Shape{
		"blocker": jsonshape.Nullable(text), "commandRefs": jsonshape.Array(text, 0),
		"evidenceRefs": jsonshape.Array(text, 0), "itemId": jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes),
		"label": text, "nonClaims": jsonshape.Array(text, 1), "owner": text, "status": jsonshape.Enum(itemStatuses),
	}
}

func InputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"checklistId": id, "items": jsonshape.Array(jsonshape.ObjectFromKeys(itemKeys, itemFields(), "blocker"), 1),
		"nextCommandRefs": jsonshape.Array(text, 0), "nonClaims": jsonshape.Array(text, 1),
		"requiredItemIds": jsonshape.Array(id, 1), "scenario": jsonshape.Enum(scenarios), "schemaVersion": jsonshape.IntegerLiteral(1),
	}).JSONSchema()
	properties := schema["properties"].(map[string]any)
	for _, key := range []string{"items", "nextCommandRefs", "nonClaims", "requiredItemIds"} {
		properties[key].(map[string]any)["uniqueItems"] = true
	}
	properties["nonClaims"].(map[string]any)["items"].(map[string]any)["not"] = map[string]any{"enum": slices.Clone(checklistNonClaims)}
	item := properties["items"].(map[string]any)["items"].(map[string]any)
	fields := item["properties"].(map[string]any)
	for _, key := range []string{"commandRefs", "evidenceRefs", "nonClaims"} {
		fields[key].(map[string]any)["uniqueItems"] = true
	}
	condition := func(status string) map[string]any {
		return map[string]any{"required": []any{"status"}, "properties": map[string]any{"status": map[string]any{"const": status}}}
	}
	item["allOf"] = []any{
		map[string]any{
			"if":   condition("blocked"),
			"then": map[string]any{"required": []any{"blocker"}, "properties": map[string]any{"blocker": text.JSONSchema()}},
			"else": map[string]any{"properties": map[string]any{"blocker": jsonshape.Null().JSONSchema()}},
		},
		map[string]any{"if": condition("satisfied"), "then": map[string]any{"properties": map[string]any{"evidenceRefs": jsonshape.Array(text, 1).JSONSchema()}}},
	}
	schema["description"] = "All root fields are required. blocker alone is optional and nullable: missing equals null; blocked items require nonempty blocker text, other statuses forbid it. Satisfied items require evidence. Items and required IDs are nonempty; command/evidence arrays may be empty. Native admission trims prose, sorts arrays, rejects normalized duplicates, repeated itemId and builtin/caller nonClaim collisions. RuleIDs are untrimmed bounded ASCII and reject secret-like and timestamp-like components. JSON Schema does not implement framing, integer token spelling, normalized uniqueness, privacy or identity-key uniqueness. Undefined required IDs and required missing/blocked/not_applicable items produce admitted failed reports; optional unsatisfied items do not block the checklist. References remain caller-owned text, not executed commands or authenticated evidence."
	return schema
}

func OutputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	state := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	fields := itemFields()
	fields["required"] = jsonshape.Boolean()
	keys := append(append([]string{}, itemKeys...), "required")
	item := jsonshape.RequiredObject(keys, fields)
	checklist := jsonshape.Object(
		jsonshape.Required("blockedRequiredItemIds", jsonshape.Array(id, 0)),
		jsonshape.Required("checklistId", id), jsonshape.Required("checklistKind", jsonshape.StringLiteral(reportKind)),
		jsonshape.Required("items", jsonshape.Array(item, 1)),
		jsonshape.Required("missingRequiredItemIds", jsonshape.Array(id, 0)),
		jsonshape.Required("nextCommandRefs", jsonshape.Array(text, 0)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, len(checklistNonClaims)+1)),
		jsonshape.Required("notApplicableRequiredItemIds", jsonshape.Array(id, 0)),
		jsonshape.Required("requiredItemIds", jsonshape.Array(id, 1)),
		jsonshape.Required("scenario", jsonshape.Enum(scenarios)), jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("state", jsonshape.Enum(map[string]struct{}{"passed": {}, "blocked": {}})),
	)
	summary := jsonshape.Object(
		jsonshape.Required("blockedRequiredCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("itemCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("missingRequiredCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("notApplicableRequiredCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("requiredItemCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("scenario", jsonshape.Enum(scenarios)),
		jsonshape.Required("satisfiedRequiredCount", jsonshape.IntegerMinimum(0)),
	)
	passed := ruleResults(nil)[0]
	rule := jsonshape.OneOf(
		report.RuleStructure(jsonshape.StringLiteral(passed.RuleID), jsonshape.StringLiteral(passed.Status), jsonshape.StringLiteral(passed.Message), jsonshape.Tuple()),
		report.RuleStructure(jsonshape.StringGrammar(`proofkit\.adoption-checklist\.failure\.[0-9]{3,}`), jsonshape.StringLiteral("failed"), text, jsonshape.Tuple()),
	)
	schema := report.Structure(1, reportKind, state, summary, jsonshape.Tuple(report.DiagnosticStructure("checklist", checklist)), jsonshape.Array(rule, 1)).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	properties["nonClaims"] = nonClaimsStructure()
	value := properties["diagnostics"].(map[string]any)["prefixItems"].([]any)[0].(map[string]any)["properties"].(map[string]any)["value"].(map[string]any)
	checklistFields := value["properties"].(map[string]any)
	checklistFields["nonClaims"] = nonClaimsStructure()
	for _, key := range []string{"blockedRequiredItemIds", "items", "missingRequiredItemIds", "nextCommandRefs", "notApplicableRequiredItemIds", "requiredItemIds"} {
		checklistFields[key].(map[string]any)["uniqueItems"] = true
	}
	itemFields := checklistFields["items"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	for _, key := range []string{"commandRefs", "evidenceRefs", "nonClaims"} {
		itemFields[key].(map[string]any)["uniqueItems"] = true
	}
	schema["description"] = "Report state passed/failed corresponds to the embedded checklist state passed/blocked. Report and checklist IDs preserve checklistId. Counts, required flags, membership, canonical order, blockers and rule messages derive from admitted input. Undeclared required IDs contribute to requiredItemCount without appearing in item-status counts. Passed reports have one fixed success rule; failures have one failed rule per failure with one-based indices padded to at least three digits. Both nonClaims arrays contain the mandatory builtin and caller claims, sorted and unique. A structural report is not evidence authentication, command execution, freshness or merge approval."
	return schema
}

func nonClaimsStructure() map[string]any {
	claims := jsonshape.Array(jsonshape.StringGrammar(`[\s\S]+`), len(checklistNonClaims)+1).JSONSchema()
	claims["uniqueItems"] = true
	contains := make([]any, 0, len(checklistNonClaims))
	for _, claim := range checklistNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	claims["allOf"] = contains
	return claims
}
