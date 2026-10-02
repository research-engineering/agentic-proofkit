package renderedartifactfreshness

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputKeys = []string{"artifacts", "freshnessSetId", "nonClaims", "schemaVersion"}
var artifactKeys = []string{"artifactFormat", "artifactId", "artifactKind", "artifactPath", "authority", "currentArtifactDigest", "currentGenerationScopeDigest", "currentRendererDigest", "currentRendererVersion", "currentSourceDigest", "freshnessCheckRefs", "generationScopeId", "nonClaims", "recordedArtifactDigest", "recordedGenerationScopeDigest", "recordedRendererDigest", "recordedRendererVersion", "recordedSourceDigest", "rendererId", "sourceRefs"}

func InputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	digest := jsonshape.StringGrammar(digestPattern.String())
	artifact := jsonshape.RequiredObject(artifactKeys, map[string]jsonshape.Shape{
		"artifactFormat": jsonshape.Enum(artifactFormats), "artifactId": id, "artifactKind": jsonshape.Enum(artifactKinds),
		"artifactPath": text, "authority": jsonshape.Enum(artifactAuthorities),
		"currentArtifactDigest": digest, "currentGenerationScopeDigest": digest, "currentRendererDigest": digest,
		"currentRendererVersion": text, "currentSourceDigest": digest, "freshnessCheckRefs": jsonshape.Array(text, 1),
		"generationScopeId": id, "nonClaims": jsonshape.Array(text, 1),
		"recordedArtifactDigest": digest, "recordedGenerationScopeDigest": digest, "recordedRendererDigest": digest,
		"recordedRendererVersion": text, "recordedSourceDigest": digest, "rendererId": id, "sourceRefs": jsonshape.Array(text, 1),
	})
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"artifacts": jsonshape.Array(artifact, 1), "freshnessSetId": id,
		"nonClaims": jsonshape.Array(text, 1), "schemaVersion": jsonshape.IntegerLiteral(1),
	}).JSONSchema()
	properties := schema["properties"].(map[string]any)
	claims := properties["nonClaims"].(map[string]any)
	claims["uniqueItems"] = true
	claims["items"].(map[string]any)["not"] = map[string]any{"enum": admit.StringSliceToAny(boundaryNonClaims)}
	artifacts := properties["artifacts"].(map[string]any)
	artifacts["uniqueItems"] = true
	fields := artifacts["items"].(map[string]any)["properties"].(map[string]any)
	for _, key := range []string{"freshnessCheckRefs", "nonClaims", "sourceRefs"} {
		fields[key].(map[string]any)["uniqueItems"] = true
	}
	schema["description"] = "All root/artifact members are required and nonnull without defaults; all arrays are nonempty. Artifacts reject duplicate artifactId and duplicate normalized artifactPath, then sort by ID; input ID/path order is unrestricted. Text/path list items trim before nonempty, sorted unique and shared privacy admission; paths then use safe repository-relative POSIX rules without existence checks. Scalar version/path text also trims. Root nonClaims must not collide with builtin nonClaims, including after trimming; the merged output is sorted and unique, not silently deduplicated. IDs are untrimmed bounded ASCII and reject secret-like or timestamp-like components. Digest strings require exact sha256:<64 lowercase hex> without trimming. schemaVersion requires literal integer token 1. JSON Schema does not establish strict framing, normalization, path/privacy checks, sorting, identity/path-key uniqueness or digest truth. All admitted authority/digest/version mismatches produce failed JSON reports rather than admission errors."
	return schema
}

func OutputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	artifact := jsonshape.Object(
		jsonshape.Required("artifactFormat", jsonshape.Enum(artifactFormats)), jsonshape.Required("artifactId", id),
		jsonshape.Required("artifactKind", jsonshape.Enum(artifactKinds)), jsonshape.Required("artifactPath", text),
		jsonshape.Required("authority", jsonshape.Enum(artifactAuthorities)), jsonshape.Required("generationScopeId", id),
		jsonshape.Required("rendererId", id),
	)
	nativeRules := ruleResults(nil)
	failures := jsonshape.Array(jsonshape.Object(
		jsonshape.Required("key", jsonshape.StringGrammar(`failure\.[0-9]{3,}`)), jsonshape.Required("value", text),
	), 0)
	schema := report.Structure(1, reportKind, status, jsonshape.Object(
		jsonshape.Required("artifactCount", jsonshape.IntegerMinimum(1)), jsonshape.Required("failureCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("generatedLookupCount", jsonshape.IntegerMinimum(0)), jsonshape.Required("renderedViewCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("staleArtifactCount", jsonshape.IntegerMinimum(0)),
	), jsonshape.Tuple(report.DiagnosticStructure("artifacts", jsonshape.Array(artifact, 1)), report.DiagnosticStructure("failures", jsonshape.Array(text, 0))),
		jsonshape.Tuple(
			report.RuleStructure(jsonshape.StringLiteral(nativeRules[0].RuleID), status, jsonshape.StringLiteral(nativeRules[0].Message), failures),
			report.RuleStructure(jsonshape.StringLiteral(nativeRules[1].RuleID), jsonshape.StringLiteral("passed"), jsonshape.StringLiteral(nativeRules[1].Message), jsonshape.Tuple()),
		),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	claims := jsonshape.Array(text, len(boundaryNonClaims)+1).JSONSchema()
	claims["uniqueItems"] = true
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, value := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": value}})
	}
	claims["allOf"], properties["nonClaims"] = contains, claims
	schema["description"] = "reportId preserves freshnessSetId; artifact diagnostics are sorted by admitted artifactId. All summary counts derive from admitted artifacts and their native failures. Failures are sorted; state and the artifacts rule fail exactly when failures exist. The boundary rule always passes. Rule/diagnostic positions and rule messages are fixed; failure keys are one-based positions padded to at least three digits. nonClaims contain all builtins and noncolliding caller claims in sorted unique order. Passed reports exit 0, admitted failed reports exit 1 with JSON; admission errors exit 1 on stderr without a report. Structural validity does not establish observed digest truth, actual freshness, witness execution or release readiness."
	return schema
}
