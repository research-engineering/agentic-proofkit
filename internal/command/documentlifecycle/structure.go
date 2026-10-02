package documentlifecycle

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputKeys = []string{"boundaryId", "documents", "nonClaims", "schemaVersion"}
var documentKeys = []string{"authorityRole", "documentId", "forbiddenPayloads", "freshnessCheckRefs", "kind", "lifecycleState", "mutationTriggers", "nonClaims", "owner", "path", "routingRole", "sourceRefs"}

func InputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	document := jsonshape.RequiredObject(documentKeys, map[string]jsonshape.Shape{
		"authorityRole": jsonshape.Enum(authorityRoles), "documentId": id,
		"forbiddenPayloads": jsonshape.Array(text, 1), "freshnessCheckRefs": jsonshape.Array(text, 0),
		"kind": jsonshape.Enum(lifecycleKinds), "lifecycleState": jsonshape.Enum(lifecycleStates),
		"mutationTriggers": jsonshape.Array(text, 1), "nonClaims": jsonshape.Array(text, 1),
		"owner": text, "path": text, "routingRole": jsonshape.Enum(routingRoles), "sourceRefs": jsonshape.Array(text, 0),
	})
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"boundaryId": id, "documents": jsonshape.Array(document, 1),
		"nonClaims": jsonshape.Array(text, 1), "schemaVersion": jsonshape.IntegerLiteral(1),
	}).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["nonClaims"].(map[string]any)["uniqueItems"] = true
	documents := properties["documents"].(map[string]any)
	documents["uniqueItems"] = true
	fields := documents["items"].(map[string]any)["properties"].(map[string]any)
	for _, key := range []string{"forbiddenPayloads", "freshnessCheckRefs", "mutationTriggers", "nonClaims", "sourceRefs"} {
		fields[key].(map[string]any)["uniqueItems"] = true
	}
	schema["description"] = "All root and document members are required and nonnull; no defaults exist. Documents are nonempty, reject repeated documentId and are sorted by that ID after admission, so unsorted input documents are valid. Text arrays preserve canonical nonempty, sorted unique text without trimming; path arrays preserve sorted unique repository-relative POSIX paths. freshnessCheckRefs and sourceRefs may be empty; the other arrays must be nonempty. Scalar owner/path text is trimmed; path then uses the shared safe repository-relative path owner without existence checks. RuleIDs are untrimmed bounded ASCII and reject secret-like or timestamp-like components. All caller-visible text is subject to shared privacy admission. schemaVersion requires integer token 1, not 1.0 or 1e0. JSON Schema does not implement framing, privacy, normalized paths, sorting or identity-key uniqueness. Admitted kind/state/authority/routing combinations that violate lifecycle boundaries produce failed reports, not admission errors."
	return schema
}

func OutputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	summary := jsonshape.Object(
		jsonshape.Required("archivedDocumentCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("currentAuthorityCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("documentCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("failureCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("historicalAuthorityCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("temporaryDocumentCount", jsonshape.IntegerMinimum(0)),
	)
	nativeRules := documentLifecycleRuleResults(nil)
	failures := jsonshape.Array(jsonshape.Object(
		jsonshape.Required("key", jsonshape.StringGrammar(`failure\.[0-9]{3,}`)),
		jsonshape.Required("value", text),
	), 0)
	schema := report.Structure(1, reportKind, status, summary,
		jsonshape.Tuple(report.DiagnosticStructure("failures", jsonshape.Array(text, 0))),
		jsonshape.Tuple(
			report.RuleStructure(jsonshape.StringLiteral(nativeRules[0].RuleID), status, jsonshape.StringLiteral(nativeRules[0].Message), failures),
			report.RuleStructure(jsonshape.StringLiteral(nativeRules[1].RuleID), jsonshape.StringLiteral("passed"), jsonshape.StringLiteral(nativeRules[1].Message), jsonshape.Tuple()),
		),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes).JSONSchema()
	claims := jsonshape.Array(text, len(boundaryNonClaims)+1).JSONSchema()
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, value := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": value}})
	}
	claims["allOf"], properties["nonClaims"] = contains, claims
	schema["description"] = "reportId preserves boundaryId; summary counts derive from admitted document records. Failures are sorted; state and the authority-demotion rule fail exactly when failures exist. The boundary rule always passes. Rule positions/messages and the failures diagnostic position are fixed; failure diagnostic keys use one-based positions padded to at least three digits. Builtin and caller nonClaims are sorted together, retaining collisions as duplicates. Passed reports exit 0, admitted failed reports exit 1 with JSON; admission errors exit 1 on stderr without a report. Structural validity does not establish document content, freshness, product semantics or merge approval."
	return schema
}
