package secretscan

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func InputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	file := jsonshape.ObjectFromKeys(fileKeys, map[string]jsonshape.Shape{
		"contentBase64": jsonshape.String(), "path": text, "state": jsonshape.Enum(fileStates),
	}, "contentBase64").JSONSchema()
	file["if"] = map[string]any{"properties": map[string]any{"state": map[string]any{"const": "present"}}}
	file["then"] = map[string]any{"required": []any{"contentBase64"}}
	file["else"] = map[string]any{"not": map[string]any{"required": []any{"contentBase64"}}}
	suppression := jsonshape.RequiredObject(suppressionKeys, map[string]jsonshape.Shape{
		"findingClass": jsonshape.Enum(findingClasses), "line": jsonshape.IntegerRange(1, int64(^uint(0)>>1)),
		"path": text, "reason": text, "suppressionId": id,
	})
	schema := jsonshape.ObjectFromKeys(inputKeys, map[string]jsonshape.Shape{
		"schemaVersion": jsonshape.IntegerLiteral(1), "reportId": id,
		"files": jsonshape.Array(jsonshape.Object(), 0), "nonClaims": jsonshape.Array(text, 0),
		"suppressions": jsonshape.Nullable(jsonshape.Array(suppression, 0)),
	}, "suppressions").JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["files"].(map[string]any)["items"] = file
	properties["nonClaims"].(map[string]any)["uniqueItems"] = true
	schema["description"] = "All members are required and nonnull except suppressions, whose absence or null means an empty list. All lists admit empty arrays. Present files require string contentBase64, including an empty string for empty bytes; missing files forbid the key. Native Build decodes standard base64 and rejects malformed encodings; JSON Schema does not decode content. Native path admission trims safe repository-relative POSIX paths and requires the file sequence sorted and unique after normalization. Suppressions sort by ID and require unique IDs and unique path/line/findingClass coordinates; line uses a positive canonical JSON integer fitting native int. NonClaims trim, reject empty or secret-like text and normalized duplicates, then sort; input order is unrestricted. IDs are untrimmed bounded ASCII with native secret/timestamp exclusions. Native admission owns these normalization, privacy, identity and integer-spelling rules. The schema does not inspect files, execute a scanner, establish credential validity or prove a finding."
	return schema
}

func OutputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	count := jsonshape.IntegerMinimum(0)
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	finding := jsonshape.Object(jsonshape.Required("findingClass", jsonshape.Enum(findingClasses)),
		jsonshape.Required("line", jsonshape.IntegerRange(1, int64(^uint(0)>>1))), jsonshape.Required("path", text))
	suppression := jsonshape.RequiredObject(suppressionKeys, map[string]jsonshape.Shape{
		"findingClass": jsonshape.Enum(findingClasses), "line": jsonshape.IntegerRange(1, int64(^uint(0)>>1)),
		"path": text, "reason": text, "suppressionId": id,
	})
	schema := report.Structure(1, reportKind, status, jsonshape.Object(
		jsonshape.Required("checkedFileCount", count), jsonshape.Required("findingCount", count),
		jsonshape.Required("inputFileCount", count), jsonshape.Required("missingSkippedFileCount", count),
		jsonshape.Required("suppressedFindingCount", count), jsonshape.Required("suppressionCount", count),
		jsonshape.Required("unusedSuppressionCount", count), jsonshape.Required("unsuppressedFindingCount", count),
	), jsonshape.Tuple(
		report.DiagnosticStructure("findings", jsonshape.Array(finding, 0)),
		report.DiagnosticStructure("suppressedFindings", jsonshape.Array(suppression, 0)),
		report.DiagnosticStructure("unusedSuppressions", jsonshape.Array(suppression, 0)),
	), jsonshape.Tuple(report.RuleStructure(jsonshape.StringLiteral("proofkit.secret-scan.explicit-inventory"), status,
		jsonshape.Enum(map[string]struct{}{ruleMessage("passed"): {}, ruleMessage("failed"): {}}),
		jsonshape.Tuple(report.DiagnosticStructure("findingCount", count), report.DiagnosticStructure("suppressedFindingCount", count),
			report.DiagnosticStructure("unusedSuppressionCount", count), report.DiagnosticStructure("unsuppressedFindingCount", count)),
	))).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	claims := jsonshape.Array(text, len(boundaryNonClaims)).JSONSchema()
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, claim := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	claims["allOf"], properties["nonClaims"] = contains, claims
	schema["description"] = "Fixed ordered diagnostic and rule tuples describe admitted explicit inventory only. Native Build derives counts, finding locations, suppression matches and ordering; a passed report has no unsuppressed findings or unused suppressions and exits0, otherwise an admitted failed report exits1. Rule status and message follow report state. Admission errors emit stderr, not this report. Output nonClaims sort two builtin statements plus normalized caller claims; a caller may repeat a builtin, so cross-origin duplicates are not forbidden. No matched content is emitted. Structural validity alone does not establish finding truth, count equality, absence of sensitive values, credential validity or repository completeness."
	return schema
}
