package changedpathset

import (
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func InputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"schemaVersion": jsonshape.IntegerLiteral(1), "reportId": id,
		"nonClaims": jsonshape.Array(text, 0), "preexistingFailures": jsonshape.Array(text, 0),
		"sources": jsonshape.Array(jsonshape.RequiredObject(sourceKeys, map[string]jsonshape.Shape{
			"sourceId": id, "paths": jsonshape.Array(jsonshape.String(), 0),
		}), 0),
	}).JSONSchema()
	schema["description"] = "All root and source fields are required and nonnull; arrays may be empty. Paths are arbitrary strings here, including empty, unsafe or repeated candidates. Native evaluation preserves accepted path bytes, including surrounding spaces, and emits a failed report for invalid or noncanonical paths rather than cleaning or trimming them; exact duplicates yield warnings and deduplication, not admission errors. Sources sort by unique sourceId; text lists trim, reject empty or sensitive items, then sort and deduplicate. NonClaims merge the builtin statements with caller claims. IDs are untrimmed bounded ASCII with native secret/timestamp exclusions. Native admission owns ID/privacy, normalized text uniqueness and literal schemaVersion spelling. JSON Schema does not authenticate changed paths or establish git freshness."
	return schema
}

func OutputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	count := jsonshape.IntegerMinimum(0)
	digest := jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	diagnostic := jsonshape.Object(jsonshape.Required("path", text), jsonshape.Required("reason", text), jsonshape.Required("sourceId", id))
	source := jsonshape.Object(
		jsonshape.Required("admittedPathCount", count), jsonshape.Required("duplicateAdmittedPathCount", count),
		jsonshape.Required("duplicateInputPathCount", count), jsonshape.Required("inputPathCount", count),
		jsonshape.Required("invalidPathCount", count), jsonshape.Required("sourceId", id),
	)
	diagnostics, sources := jsonshape.Array(diagnostic, 0), jsonshape.Array(source, 0)
	schema := report.Structure(1, "proofkit.changed-path-set", status,
		jsonshape.Object(jsonshape.Required("changedPathCount", count), jsonshape.Required("duplicatePathCount", count),
			jsonshape.Required("invalidPathCount", count), jsonshape.Required("sourceCount", count)),
		jsonshape.Tuple(report.DiagnosticStructure("changedPathSetHash", digest), report.DiagnosticStructure("duplicatePaths", diagnostics),
			report.DiagnosticStructure("invalidPaths", diagnostics), report.DiagnosticStructure("sourceSummaries", sources)),
		jsonshape.Tuple(
			report.RuleStructure(jsonshape.StringLiteral("changed_path_set.admission"), status,
				jsonshape.Enum(map[string]struct{}{"all caller-supplied changed paths are admitted": {}, "caller-supplied changed paths include invalid entries": {}}), jsonshape.Tuple()),
			report.RuleStructure(jsonshape.StringLiteral("changed_path_set.duplicates"), jsonshape.Enum(map[string]struct{}{"passed": {}, "warning": {}}),
				jsonshape.Enum(map[string]struct{}{"no duplicate changed path evidence": {}, "duplicate changed path evidence was deduplicated": {}}), jsonshape.Tuple()),
			report.RuleStructure(jsonshape.StringLiteral("changed_path_set.preexisting_failures"), status,
				jsonshape.Enum(map[string]struct{}{"no caller preexisting failures": {}, "caller supplied preexisting failures": {}}), jsonshape.Tuple()),
		),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	claims := jsonshape.Array(text, len(changedPathSetNonClaims)).JSONSchema()
	claims["uniqueItems"] = true
	contains := make([]any, 0, len(changedPathSetNonClaims))
	for _, claim := range changedPathSetNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	claims["allOf"], properties["nonClaims"] = contains, claims
	required := schema["required"].([]any)
	for name, shape := range map[string]jsonshape.Shape{
		"changedPathSetHash": digest, "changedPaths": jsonshape.Array(text, 0),
		"duplicatePaths": diagnostics, "failures": jsonshape.Array(text, 0),
		"invalidPaths": diagnostics, "sourceSummaries": sources,
	} {
		properties[name] = shape.JSONSchema()
		required = append(required, name)
	}
	sort.Slice(required, func(i, j int) bool { return required[i].(string) < required[j].(string) })
	schema["required"] = required
	schema["description"] = "The report retains admitted sorted unique paths and their stable hash, source summaries, minimized invalid-path diagnostics and deduplication warnings. All report fields are required. Variable path, failure, source-summary and per-key diagnostic collections may be empty; diagnostics has exactly four ordered records and ruleResults exactly three. NonClaims contains the nonempty sorted unique builtin/caller union. Native Build owns repeated-field equality, counts, hash truth, ordering and relations: report state fails for invalid paths or preexisting failures; duplicate evidence alone is a warning. Each rule has its own fixed ordered ID and corresponding status/message alternatives. Admission errors emit stderr without a report. Shape validity proves neither source freshness/completeness nor selective-gate adequacy."
	return schema
}
