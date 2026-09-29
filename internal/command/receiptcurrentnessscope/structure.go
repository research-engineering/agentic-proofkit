package receiptcurrentnessscope

import (
	"regexp"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func InputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.String()
	texts := jsonshape.Array(text, 1)
	digest := jsonshape.StringGrammar(digestPatternBody)
	current := jsonshape.RequiredObject(currentnessKeys, map[string]jsonshape.Shape{
		"checkClass": id, "checkId": id, "currentDigest": digest,
		"evidenceRefs": texts, "nonClaims": texts, "recordedDigest": digest,
	})
	scope := jsonshape.RequiredObject(scopeKeys, map[string]jsonshape.Shape{
		"admissionState": jsonshape.Enum(scopeAdmissionStateSet), "checkId": id,
		"currentScopeDigest": jsonshape.Nullable(digest), "evidenceRefs": texts,
		"nonClaims": texts, "reason": text, "recordedScopeDigest": jsonshape.Nullable(digest), "scopeClass": id,
	})
	receipt := jsonshape.RequiredObject(obligationKeys, map[string]jsonshape.Shape{
		"currentnessChecks": jsonshape.Array(current, 1), "evidenceRefs": texts,
		"nonClaims": texts, "obligationId": id, "owner": text, "proofRouteRef": id,
		"reason": text, "receiptId": id, "requirementId": id, "scopeChecks": jsonshape.Array(scope, 1),
	})
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"admissionId": id, "nonClaims": texts, "obligationReceipts": jsonshape.Array(receipt, 1),
		"schemaVersion": jsonshape.IntegerLiteral(1),
	}).JSONSchema()
	annotateUniqueCarrier(schema)
	schema["description"] = "All members are required; both scope digest members explicitly admit null but not absence. No defaults are inserted. Scalar identifiers, enum values and sha256 digests are exact and untrimmed. Native identifiers additionally reject secret-like and timestamp-like text. Prose and nonClaims are trimmed to nonempty text; normalized duplicates reject. Evidence refs use the shared canonical repository-relative POSIX path owner, not prose admission or file existence checks. Obligation IDs and each receipt's check IDs are unique; native admission sorts these records. Root nonClaims must not collide with builtin nonClaims, including after trimming. The CLI admits bounded strict UTF-8 JSON with no duplicate members and requires the canonical integer token 1. Structural admission does not establish receipt currentness or scope truth: admitted stale, unknown-scope and not-applicable declarations still produce reports."
	return schema
}

func OutputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	texts := jsonshape.Array(jsonshape.String(), 0)
	states := jsonshape.OneOf(jsonshape.Tuple(),
		jsonshape.Tuple(jsonshape.StringLiteral("stale_receipt")),
		jsonshape.Tuple(jsonshape.StringLiteral("unknown_scope")),
		jsonshape.Tuple(jsonshape.StringLiteral("stale_receipt"), jsonshape.StringLiteral("unknown_scope")),
		jsonshape.Tuple(jsonshape.StringLiteral("not_applicable")))
	diagnostic := jsonshape.Object(
		jsonshape.Required("currentnessFindings", texts), jsonshape.Required("decisionCandidateStates", states),
		jsonshape.Required("obligationId", id), jsonshape.Required("proofRouteRef", id),
		jsonshape.Required("receiptId", id), jsonshape.Required("requirementId", id),
		jsonshape.Required("scopeFindings", texts),
	)
	rule := report.RuleStructure(
		jsonshape.BoundedStringGrammar(regexp.QuoteMeta(ruleIDPrefix)+"(?:"+admit.RuleIDPatternBody+")", len(ruleIDPrefix)+admit.MaxRuleIDBytes),
		jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}, "skipped": {}}), jsonshape.String(),
		jsonshape.Tuple(report.DiagnosticStructure("receiptCurrentnessScope", diagnostic)),
	)
	schema := report.Structure(1, reportKind, jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}}),
		jsonshape.Object(
			jsonshape.Required("currentReceiptCount", jsonshape.IntegerMinimum(0)),
			jsonshape.Required("currentnessFindingCount", jsonshape.IntegerMinimum(0)),
			jsonshape.Required("failedObligationCount", jsonshape.IntegerMinimum(0)),
			jsonshape.Required("notApplicableCount", jsonshape.IntegerMinimum(0)),
			jsonshape.Required("obligationReceiptCount", jsonshape.IntegerMinimum(1)),
			jsonshape.Required("scopeFindingCount", jsonshape.IntegerMinimum(0)),
			jsonshape.Required("staleReceiptCount", jsonshape.IntegerMinimum(0)),
			jsonshape.Required("unknownScopeCount", jsonshape.IntegerMinimum(0)),
		),
		jsonshape.Tuple(report.DiagnosticStructure("failedObligationIds", jsonshape.Array(id, 0)),
			report.DiagnosticStructure("receiptCurrentnessScope", jsonshape.Array(diagnostic, 1))),
		jsonshape.Array(rule, 1),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	nonClaims := properties["nonClaims"].(map[string]any)
	nonClaims["minItems"] = len(boundaryNonClaims) + 1
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, value := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": value}})
	}
	nonClaims["allOf"] = contains
	annotateUniqueCarrier(schema)
	schema["description"] = "Reports preserve the admitted admissionId. Diagnostic and rule records follow sorted obligation IDs; findings and merged nonClaims are sorted. Each rule ID prefixes its obligation ID and each nested rule diagnostic equals the corresponding top-level diagnostic. Counts derive from these records. Digest mismatch adds stale_receipt; rejected, unknown or mismatched scope adds unknown_scope; not_applicable appears alone only when all scopes are not applicable and no finding exists. A rule fails on findings, otherwise skips for not_applicable, otherwise passes. The report fails iff any obligation has findings. Admitted passed reports exit 0; admitted failed reports exit 1 with JSON. Admission errors exit 1 on stderr without a report. Schema validity does not authenticate callers, establish freshness, execute witnesses or approve merge."
	return schema
}

// Every array in this family's carrier is a set, a keyed inventory, or a
// fixed tuple with distinct members. Normalized uniqueness remains native.
func annotateUniqueCarrier(value any) {
	switch value := value.(type) {
	case map[string]any:
		if value["type"] == "array" {
			value["uniqueItems"] = true
		}
		if value["type"] == "string" {
			value["minLength"] = 1
		}
		for _, child := range value {
			annotateUniqueCarrier(child)
		}
	case []any:
		for _, child := range value {
			annotateUniqueCarrier(child)
		}
	}
}
