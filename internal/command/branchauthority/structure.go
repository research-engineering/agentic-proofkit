package branchauthority

import (
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const branchDescription = "Native branchName admission preserves the original string: trimming must not change it. It rejects HEAD, a leading hyphen, a trailing dot, @{, .., //, leading/trailing slash, components starting with dot or ending with .lock, ASCII control/DEL, the space character and ~^:?*[\\. The shared secret-like text policy also applies. This is a declared branch observation, not repository discovery or proof of a live branch."

// InputStructure describes the carrier; native annotations do not turn JSON
// Schema validation into framing, normalization or semantic evaluation.
func InputStructure() map[string]any {
	shape := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"schemaVersion":       jsonshape.IntegerLiteral(1),
		"reportId":            jsonshape.StringGrammar(admit.RuleIDPatternBody),
		"branchRefs":          jsonshape.Array(jsonshape.RequiredObject(refKeys, refFields()), 1),
		"preexistingFailures": jsonshape.Array(jsonshape.String(), 0),
		"nonClaims":           jsonshape.Array(jsonshape.String(), 1),
	})
	schema := shape.JSONSchema()
	schema["description"] = "All fields are required, non-null and have no defaults. The CLI applies its shared strict UTF-8, single-document, duplicate-member and bounded-input admission before JSON Pointer selection. schemaVersion requires the literal integer token 1, not 1.0 or 1e0. Native admission rejects repeated refId values even when the remaining ref fields differ, then sorts refs by exact refId; identifiers are not trimmed or case-folded. Text arrays are trimmed and sorted, and duplicate normalized values are rejected. Root nonClaims are merged with the required builtin nonClaims; collisions with those builtins also reject, including collisions after trimming. JSON Schema alone does not perform these native transformations, privacy checks or cross-record checks."
	properties := schema["properties"].(map[string]any)
	describeIdentifier(properties["reportId"].(map[string]any))
	describeRef(properties["branchRefs"].(map[string]any)["items"].(map[string]any))
	describeTexts(properties["preexistingFailures"].(map[string]any))
	nonClaims := properties["nonClaims"].(map[string]any)
	describeTexts(nonClaims)
	nonClaims["items"].(map[string]any)["not"] = map[string]any{"enum": slices.Clone(branchAuthorityNonClaims)}
	return schema
}

func OutputStructure() map[string]any {
	refs := refFields()
	refs["alignment"] = jsonshape.Enum(map[string]struct{}{"aligned": {}, "drifted": {}})
	outputRef := jsonshape.RequiredObject(append(slices.Clone(refKeys), "alignment"), refs)
	identifiers := jsonshape.Array(jsonshape.StringGrammar(admit.RuleIDPatternBody), 0)
	shape := report.Structure(1, reportKind,
		jsonshape.Enum(map[string]struct{}{statusFailedIf(false): {}, statusFailedIf(true): {}}),
		jsonshape.Object(
			jsonshape.Required("advisoryDriftCount", jsonshape.IntegerMinimum(0)),
			jsonshape.Required("branchRefCount", jsonshape.IntegerMinimum(1)),
			jsonshape.Required("requiredDriftCount", jsonshape.IntegerMinimum(0)),
		),
		jsonshape.Tuple(
			report.DiagnosticStructure("advisoryDriftRefIds", identifiers),
			report.DiagnosticStructure("branchRefs", jsonshape.Array(outputRef, 1)),
			report.DiagnosticStructure("requiredDriftRefIds", identifiers),
		),
		jsonshape.Tuple(
			ruleResultStructure(advisoryRuleID, statusWarningIf, messageAdvisory),
			ruleResultStructure(preexistingRuleID, statusFailedIf, messagePreexisting),
			ruleResultStructure(requiredRuleID, statusFailedIf, messageRequired),
		),
	)
	schema := shape.JSONSchema()
	schema["description"] = "An admitted report preserves reportId and the admitted branch observations. Refs and drift ID lists are sorted by exact refId; normalized nonClaims are sorted and unique. alignment is aligned exactly when observedBranch equals expectedBranch. Required/advisory drift lists partition drifted refs according to required; each summary count equals the corresponding array length. State is failed exactly when required drift or caller preexisting failures exist, otherwise passed. Advisory drift changes only the first rule to warning. Rule status/message pairs and diagnostic/rule positions are fixed. A passed report exits 0; an admitted failed report exits 1 with JSON output. Admission failure exits 1 on stderr without a report. Structural validity does not establish caller-evidence truth, repository settings or approval."
	properties := schema["properties"].(map[string]any)
	describeIdentifier(properties["reportId"].(map[string]any))
	diagnostics := properties["diagnostics"].(map[string]any)["prefixItems"].([]any)
	for _, index := range []int{0, 2} {
		value := diagnostics[index].(map[string]any)["properties"].(map[string]any)["value"].(map[string]any)
		value["uniqueItems"] = true
		describeIdentifier(value["items"].(map[string]any))
	}
	refArray := diagnostics[1].(map[string]any)["properties"].(map[string]any)["value"].(map[string]any)
	describeRef(refArray["items"].(map[string]any))
	nonClaims := properties["nonClaims"].(map[string]any)
	describeTexts(nonClaims)
	nonClaims["minItems"] = len(branchAuthorityNonClaims) + 1
	contains := make([]any, 0, len(branchAuthorityNonClaims))
	for _, text := range branchAuthorityNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": text}})
	}
	nonClaims["allOf"] = contains
	return schema
}

func refFields() map[string]jsonshape.Shape {
	return map[string]jsonshape.Shape{
		"evidenceRef":    jsonshape.String(),
		"expectedBranch": jsonshape.String(),
		"nonClaims":      jsonshape.Array(jsonshape.String(), 1),
		"observedBranch": jsonshape.String(),
		"refId":          jsonshape.StringGrammar(admit.RuleIDPatternBody),
		"refKind":        jsonshape.Enum(refKinds),
		"required":       jsonshape.Boolean(),
	}
}

func describeIdentifier(schema map[string]any) {
	schema["pattern"] = jsonshape.StringGrammar(admit.RuleIDPatternBody).JSONSchema()["pattern"]
	schema["maxLength"] = admit.MaxRuleIDBytes
	schema["description"] = "Native RuleID admission uses the declared ASCII grammar and byte bound, without trimming, case-folding or Unicode normalization. It additionally rejects secret-like values and timestamp-like identity components under the shared admission owner; the structural pattern alone does not perform those checks."
}

func describeTexts(schema map[string]any) {
	schema["uniqueItems"] = true
	schema["items"].(map[string]any)["minLength"] = 1
	schema["description"] = "Native text admission trims each item, requires a nonempty result and rejects secret-like values. Normalized duplicates reject; admitted values are sorted. These normalization/privacy checks are not implemented by the structural schema."
}

func describeRef(schema map[string]any) {
	properties := schema["properties"].(map[string]any)
	describeIdentifier(properties["refId"].(map[string]any))
	describeTexts(properties["nonClaims"].(map[string]any))
	for _, key := range []string{"observedBranch", "expectedBranch"} {
		branch := properties[key].(map[string]any)
		branch["minLength"], branch["description"] = 1, branchDescription
	}
	evidence := properties["evidenceRef"].(map[string]any)
	evidence["minLength"] = 1
	evidence["description"] = "Native admission trims nonempty text and rejects secret-like values. This reference is not resolved, read, authenticated or checked as a repository path."
}

func ruleResultStructure(id string, status func(bool) string, message func(int) string) jsonshape.Shape {
	variant := func(active bool, count int) jsonshape.Shape {
		return report.RuleStructure(jsonshape.StringLiteral(id), jsonshape.StringLiteral(status(active)),
			jsonshape.StringLiteral(message(count)), jsonshape.Tuple())
	}
	return jsonshape.OneOf(variant(false, 0), variant(true, 1))
}
