package textpolicy

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputKeys = []string{"files", "nonClaims", "policy", "reportId", "schemaVersion"}
var policyKeys = []string{"allowTab", "asciiOnly", "binarySuffixes", "rejectTrailingWhitespace", "requireFinalNewline"}
var fileKeys = []string{"contentBase64", "path", "state"}

func policyStructure() jsonshape.Shape {
	return jsonshape.RequiredObject(policyKeys, map[string]jsonshape.Shape{
		"allowTab": jsonshape.Boolean(), "asciiOnly": jsonshape.Boolean(),
		"binarySuffixes":           jsonshape.Array(jsonshape.StringGrammar(`\.[^/\\]*`), 0),
		"rejectTrailingWhitespace": jsonshape.Boolean(), "requireFinalNewline": jsonshape.Boolean(),
	})
}

func InputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"files": jsonshape.Array(jsonshape.ObjectFromKeys(fileKeys, map[string]jsonshape.Shape{
			"contentBase64": jsonshape.String(), "path": text, "state": jsonshape.Enum(fileStates),
		}, "contentBase64"), 0),
		"nonClaims": jsonshape.Array(text, 0), "policy": policyStructure(),
		"reportId": jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes), "schemaVersion": jsonshape.IntegerLiteral(1),
	}).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["nonClaims"].(map[string]any)["uniqueItems"] = true
	files := properties["files"].(map[string]any)
	files["uniqueItems"] = true
	file := files["items"].(map[string]any)
	file["if"] = map[string]any{"required": []any{"state"}, "properties": map[string]any{"state": map[string]any{"const": "missing"}}}
	file["then"] = map[string]any{"not": map[string]any{"required": []any{"contentBase64"}}}
	properties["policy"].(map[string]any)["properties"].(map[string]any)["binarySuffixes"].(map[string]any)["uniqueItems"] = true
	schema["description"] = "All root/policy members and file path/state are required. contentBase64 is optional nonnull text, including the empty string; missing files forbid its presence. Present text files without content or with invalid base64/UTF-8 produce admitted failed reports. Binary-suffix skipping precedes missing/decode checks, so even malformed base64 text is admitted and skipped for a binary candidate. Decoded scanner content is raw data, not report-visible prose. Every policy boolean admits both true and false. Paths preserve spaces and require sorted unique safe repository-relative POSIX values. Suffixes are sorted unique canonical lowercase dotted strings without separators. Root nonClaims are trimmed, sorted and reject normalized duplicates; builtin collisions are retained in output. Native admission owns privacy, path safety, ordering, lowercase and integer token spelling; schema does not claim content decoding."
	return schema
}

func OutputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	count := jsonshape.IntegerMinimum(0)
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	rule := report.RuleStructure(jsonshape.StringLiteral(reportKind+".admitted-policy"), status,
		jsonshape.Enum(map[string]struct{}{ruleMessage("passed"): {}, ruleMessage("failed"): {}}),
		jsonshape.Tuple(report.DiagnosticStructure("failureCount", count)))
	schema := report.Structure(1, reportKind, status, jsonshape.Object(
		jsonshape.Required("admittedPolicy", policyStructure()), jsonshape.Required("binarySkippedFileCount", count),
		jsonshape.Required("checkedTextFileCount", count), jsonshape.Required("failureCount", count),
		jsonshape.Required("inputFileCount", count), jsonshape.Required("missingSkippedFileCount", count),
	), jsonshape.Tuple(report.DiagnosticStructure("failures", jsonshape.Array(text, 0))), jsonshape.Tuple(rule)).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes).JSONSchema()
	claims := jsonshape.Array(text, len(standardNonClaims)).JSONSchema()
	contains := make([]any, 0, len(standardNonClaims))
	for _, claim := range standardNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	claims["allOf"], properties["nonClaims"] = contains, claims
	policy := properties["summary"].(map[string]any)["properties"].(map[string]any)["admittedPolicy"].(map[string]any)
	policy["properties"].(map[string]any)["binarySuffixes"].(map[string]any)["uniqueItems"] = true
	schema["description"] = "ReportId preserves reportId. Summary policy preserves admitted booleans and sorted unique suffixes. Failure messages are sorted and never contain raw decoded file content. Counts, rule status/message and overall state derive from the native text checks. Empty inventories and empty file content are admitted. Invalid decoding is failed data and does not increase checkedTextFileCount. Sorted nonClaims contain both builtins; caller/builtin collisions remain duplicated. Structural validity does not prove count equality, actual file contents, repository discovery, proof freshness or merge/release approval."
	return schema
}
