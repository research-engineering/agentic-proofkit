package customruleboundary

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputKeys = []string{"boundaryId", "nonClaims", "profileRef", "rules", "schemaVersion"}
var ruleKeys = []string{"affectedPathGlobs", "boundaryRole", "credentialPolicy", "deterministicOutput", "genericDecisionEffect", "genericFindingEffect", "inputArtifactKinds", "inputArtifactRefs", "namespace", "networkPolicy", "nonClaims", "outputSchemaRef", "owner", "remediation", "removal", "ruleId", "severity", "useLimit"}
var deterministicKeys = []string{"secretRedaction", "stableFindingIds", "stableOrdering"}
var remediationKeys = []string{"commandRefs", "kind", "summary"}
var useLimitKeys = []string{"maxAffectedPathGlobs", "rationale", "scope"}
var removalKeys = []string{"condition", "owner", "reviewRef"}

func InputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	rule := jsonshape.RequiredObject(ruleKeys, map[string]jsonshape.Shape{
		"affectedPathGlobs": jsonshape.Array(text, 1), "boundaryRole": jsonshape.Enum(boundaryRoles),
		"credentialPolicy": jsonshape.Enum(credentialPolicies),
		"deterministicOutput": jsonshape.RequiredObject(deterministicKeys, map[string]jsonshape.Shape{
			"secretRedaction": jsonshape.Boolean(), "stableFindingIds": jsonshape.Boolean(), "stableOrdering": jsonshape.Boolean(),
		}),
		"genericDecisionEffect": jsonshape.Enum(decisionEffects), "genericFindingEffect": jsonshape.Enum(findingEffects),
		"inputArtifactKinds": jsonshape.Array(id, 1), "inputArtifactRefs": jsonshape.Array(text, 1),
		"namespace": id, "networkPolicy": jsonshape.Enum(networkPolicies), "nonClaims": jsonshape.Array(text, 1),
		"outputSchemaRef": text, "owner": text,
		"remediation": jsonshape.RequiredObject(remediationKeys, map[string]jsonshape.Shape{
			"commandRefs": jsonshape.Array(text, 0), "kind": jsonshape.Enum(remediationKinds), "summary": text,
		}),
		"removal": jsonshape.RequiredObject(removalKeys, map[string]jsonshape.Shape{"condition": text, "owner": text, "reviewRef": text}),
		"ruleId":  id, "severity": jsonshape.Enum(severities),
		"useLimit": jsonshape.RequiredObject(useLimitKeys, map[string]jsonshape.Shape{
			"maxAffectedPathGlobs": jsonshape.IntegerRange(1, int64(^uint(0)>>1)), "rationale": text, "scope": jsonshape.Enum(scopes),
		}),
	})
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"boundaryId": id, "nonClaims": jsonshape.Array(text, 1), "profileRef": text,
		"rules": jsonshape.Array(rule, 1), "schemaVersion": jsonshape.IntegerLiteral(1),
	}).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["nonClaims"].(map[string]any)["uniqueItems"] = true
	rules := properties["rules"].(map[string]any)
	rules["uniqueItems"] = true
	fields := rules["items"].(map[string]any)["properties"].(map[string]any)
	for _, key := range []string{"affectedPathGlobs", "inputArtifactKinds", "inputArtifactRefs", "nonClaims"} {
		fields[key].(map[string]any)["uniqueItems"] = true
	}
	fields["remediation"].(map[string]any)["properties"].(map[string]any)["commandRefs"].(map[string]any)["uniqueItems"] = true
	schema["description"] = "Every root, rule and nested metadata member is required and nonnull, without defaults. Rules are nonempty, reject duplicate ruleId and are sorted by ID after admission; unsorted input rules are valid. All rule/root arrays are nonempty except remediation.commandRefs, which may be empty. Text/ref lists preserve canonical sorted unique values without trimming; refs use safe repository-relative POSIX paths. Globs trim before sorted unique admission and the shared path-pattern compiler. Scalar prose and scalar path refs trim before nonempty/privacy/path admission. IDs are untrimmed bounded ASCII and reject secret-like or timestamp-like components. maxAffectedPathGlobs requires a positive canonical native int token (host int range), while schemaVersion requires literal integer token 1. JSON Schema does not prove framing, sorting, privacy, glob/path grammar or identity-key uniqueness. Namespace ownership, finding/decision monotonicity, no network/credentials, deterministic flags, glob count/scope, remediation consistency and concrete removal are native evaluation: violations yield admitted failed reports rather than malformed input."
	return schema
}

func OutputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	nativeRules := customRuleRuleResults(nil)
	failures := jsonshape.Array(jsonshape.Object(
		jsonshape.Required("key", jsonshape.StringGrammar(`failure\.[0-9]{3,}`)), jsonshape.Required("value", text),
	), 0)
	schema := report.Structure(1, reportKind, status, jsonshape.Object(
		jsonshape.Required("customRuleCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("errorSeverityCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("failureCount", jsonshape.IntegerMinimum(0)),
	), jsonshape.Tuple(report.DiagnosticStructure("failures", jsonshape.Array(text, 0)), report.DiagnosticStructure("profileRef", text)),
		jsonshape.Tuple(
			report.RuleStructure(jsonshape.StringLiteral(nativeRules[0].RuleID), jsonshape.StringLiteral("passed"), jsonshape.StringLiteral(nativeRules[0].Message), jsonshape.Tuple()),
			report.RuleStructure(jsonshape.StringLiteral(nativeRules[1].RuleID), status, jsonshape.StringLiteral(nativeRules[1].Message), failures),
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
	schema["description"] = "reportId preserves boundaryId and profileRef preserves its admitted path. Summary counts derive from admitted rules. Failures are sorted; state and the monotone-removable rule fail exactly when failures exist. The boundary rule always passes. Rule/diagnostic positions and rule messages are fixed; failure keys are one-based positions padded to at least three digits. Builtin/caller nonClaims are sorted together with valid collision duplicates. Passed reports exit 0, admitted failed reports exit 1 with JSON; admission errors exit 1 on stderr without a report. This metadata report does not execute or authenticate custom rules, prove their findings, or approve generic decision changes."
	return schema
}
