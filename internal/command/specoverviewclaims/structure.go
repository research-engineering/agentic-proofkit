package specoverviewclaims

import (
	"math"
	"regexp"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func InputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.NonBlankString()
	claim := jsonshape.RequiredObject(claimKeys, map[string]jsonshape.Shape{
		"citedRequirementIds": jsonshape.Array(id, 0), "claimId": id,
		"claimKind": jsonshape.Enum(claimKindSet), "detectedMarkers": jsonshape.Array(text, 1),
		"dispositionRationale": text, "lineDigest": jsonshape.StringGrammar(`sha256:[a-f0-9]{64}`),
		"lineNumber": jsonshape.IntegerRange(1, math.MaxInt64), "nonClaims": jsonshape.Array(text, 1),
	})
	schema := jsonshape.RequiredObject(boundaryKeys, map[string]jsonshape.Shape{
		"boundaryId": id, "claims": jsonshape.Array(claim, 0), "extractionRefs": jsonshape.Array(text, 1),
		"nonClaims": jsonshape.Array(text, 1), "overviewPath": text, "requirementIds": jsonshape.Array(id, 1),
		"requirementsPath": text, "schemaVersion": jsonshape.IntegerLiteral(1), "sourceId": id, "specPackagePath": text,
	}).JSONSchema()
	properties := schema["properties"].(map[string]any)
	claimProperties := properties["claims"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	for _, array := range []any{properties["requirementIds"], claimProperties["citedRequirementIds"]} {
		array.(map[string]any)["items"].(map[string]any)["allOf"] = []any{map[string]any{"pattern": "^" + regexp.QuoteMeta(requirementIDPrefix)}}
	}
	schema["description"] = "All ten root and eight claim fields are required and nonnull. Claims and citedRequirementIds may be empty; all other arrays are nonempty. Claim input order is arbitrary and normalizes by unique claimId. Other normalized ID, path and text arrays must already be sorted and unique. IDs are untrimmed bounded ASCII with native secret/timestamp exclusions; requirement IDs start with REQ-. Other text trims and rejects blank or sensitive values; paths additionally require safe repository-relative paths. Digests and kinds do not trim. lineNumber is a canonical positive int64 token fitting the target int; standard JSON Schema integer values do not prove lexical spelling or lossless JS numeric decoding. Native evaluation owns derived path equality, citation membership/disposition and privacy: their semantic violations may produce a failed report rather than admission error. These extraction facts do not prove Markdown contents, source-record validity or extractor completeness."
	return schema
}

func OutputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text, count := jsonshape.NonBlankString(), jsonshape.IntegerMinimum(0)
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	summary := jsonshape.Object(
		jsonshape.Required("citedDurableClaimCount", count), jsonshape.Required("claimCount", count),
		jsonshape.Required("durableClaimCount", count), jsonshape.Required("extractionRefCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("failureCount", count), jsonshape.Required("nonNormativeClaimCount", count),
		jsonshape.Required("requirementIdCount", jsonshape.IntegerMinimum(1)), jsonshape.Required("uncitedDurableClaimCount", count),
	)
	overview := jsonshape.Object(jsonshape.Required("overviewPath", text), jsonshape.Required("requirementsPath", text), jsonshape.Required("specPackagePath", text))
	failures := jsonshape.Array(jsonshape.Object(jsonshape.Required("key", jsonshape.StringGrammar(`failure\.[0-9]{3,}`)), jsonshape.Required("value", text)), 0)
	rule := func(ruleID, message string) jsonshape.Shape {
		return report.RuleStructure(jsonshape.StringLiteral(ruleID), status, jsonshape.StringLiteral(message), failures)
	}
	schema := report.Structure(1, reportKind, status, summary,
		jsonshape.Tuple(report.DiagnosticStructure("failures", jsonshape.Array(text, 0)), report.DiagnosticStructure("overview", overview)),
		jsonshape.Tuple(rule(boundaryRuleID, boundaryRuleMessage), rule(citationRuleID, citationRuleMessage)),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	claims := jsonshape.Array(text, len(boundaryNonClaims)+1).JSONSchema()
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, claim := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	claims["allOf"], properties["nonClaims"] = contains, claims
	schema["description"] = "Every root, summary, overview and rule field is required and nonnull. Diagnostics has two ordered entries; ruleResults has the two fixed ordered IDs/messages and passed/failed statuses. Failure lists may be empty. Eight nonnegative summary counts, report state, rule state, repeated failure values and sequential failure.NNN keys have native dependent relations. NonClaims is the sorted builtin/caller concatenation, not a set: multiplicity is retained when a caller repeats a builtin statement. Native Build owns count coherence, path equality and citation interpretation. Admission errors emit stderr without a report. This report grants no requirement, extractor-completeness, merge, release, rollout or production authority."
	return schema
}
