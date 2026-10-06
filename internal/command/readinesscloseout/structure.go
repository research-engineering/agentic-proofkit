package readinesscloseout

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputFields = []string{"environmentPreconditions", "exactCommand", "frontier", "inputDefinitions", "markdownText", "negatedNonClaimPhrases", "nonClaims", "phraseRules", "readinessRowPrefixes", "readinessSections", "reportId", "runIdentity", "schemaVersion"}
var definitionFields = []string{"classification", "evidenceClass", "expectedStatus", "forbiddenText", "reason", "requiredText", "rowId"}
var frontierFields = []string{"closedRequiredText", "closedRowRequiredText", "closedStatus", "openRequiredText", "openStatus", "rowId"}
var phraseRuleFields = []string{"directClaimPhrases", "evidencePhrases", "failureMessage", "predicatePhrases", "ruleId", "subjectPhrases"}

func normalizedGrammar(body string) jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(class string) string {
		return "[" + class + "]*(?:" + body + ")[" + class + "]*"
	})
}

func InputStructure() map[string]any {
	id, text := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes), jsonshape.NonBlankString()
	texts := jsonshape.Array(text, 0)
	definition := jsonshape.ObjectFromKeys(definitionFields, map[string]jsonshape.Shape{
		"classification": jsonshape.Enum(classificationSet), "evidenceClass": id, "expectedStatus": normalizedGrammar(statusPatternBody),
		"forbiddenText": texts, "reason": text, "requiredText": texts, "rowId": normalizedGrammar(rowIDPatternBody),
	}, "forbiddenText")
	frontier := jsonshape.ObjectFromKeys(frontierFields, map[string]jsonshape.Shape{
		"closedRequiredText": texts, "closedRowRequiredText": texts, "closedStatus": normalizedGrammar(statusPatternBody),
		"openRequiredText": texts, "openStatus": normalizedGrammar(statusPatternBody), "rowId": normalizedGrammar(rowIDPatternBody),
	})
	phrase := jsonshape.ObjectFromKeys(phraseRuleFields, map[string]jsonshape.Shape{
		"directClaimPhrases": texts, "evidencePhrases": texts, "failureMessage": text,
		"predicatePhrases": texts, "ruleId": id, "subjectPhrases": texts,
	}, "directClaimPhrases")
	schema := jsonshape.ObjectFromKeys(inputFields, map[string]jsonshape.Shape{
		"schemaVersion": jsonshape.IntegerLiteral(1), "reportId": id, "runIdentity": id,
		"environmentPreconditions": texts, "exactCommand": text, "frontier": frontier,
		"inputDefinitions": jsonshape.Array(definition, 0), "markdownText": jsonshape.String(),
		"negatedNonClaimPhrases": texts, "nonClaims": texts, "phraseRules": jsonshape.Array(phrase, 0),
		"readinessRowPrefixes": texts, "readinessSections": jsonshape.Array(text, 1),
	}).JSONSchema()
	schema["description"] = "All thirteen root fields and six frontier fields are required. Definition forbiddenText and phrase directClaimPhrases are optional; present null is rejected. Definitions/rules and ordinary text arrays may be empty; readinessSections is nonempty. Raw RuleIDs are boundedASCII; row IDs and status text trim by native UnicodeWhiteSpace and have no added length bound. Native admission owns NUL/privacy/display-only command/scoped-negation checks, normalized uniqueness for environmentPreconditions/sections/prefixes/suppressors and unique definition/rule IDs. required/forbidden/phrase arrays retain order and duplicates. Markdown is caller analysis input, may be empty and is not a report sink. Native Build owns row/phrase parsing, classification honesty and dependent report facts; no execution or readiness proof is inferred."
	return schema
}

func OutputStructure() map[string]any {
	id, text, count := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes), jsonshape.NonBlankString(), jsonshape.IntegerMinimum(0)
	state := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	row, status := jsonshape.StringGrammar(rowIDPatternBody), jsonshape.StringGrammar(statusPatternBody)
	texts, rows := jsonshape.Array(text, 0), jsonshape.Array(row, 0)
	command := report.DiagnosticStructure("exactCommand", text)
	environment := report.DiagnosticStructure("environmentPreconditions", texts)
	run := report.DiagnosticStructure("runIdentity", id)
	rowBody := rowIDPatternBody
	unique := report.RuleStructure(jsonshape.StringGrammar(rowBody+`\.backlog_rows\.unique`), state, text,
		jsonshape.Tuple(report.DiagnosticStructure("duplicateFailures", texts), environment, command, run))
	classification := report.RuleStructure(jsonshape.StringGrammar(rowBody+`\.`+rowBody+`\.classification`), state, text,
		jsonshape.Tuple(report.DiagnosticStructure("classification", jsonshape.Enum(classificationSet)), environment,
			report.DiagnosticStructure("evidenceClass", id), command, report.DiagnosticStructure("expectedStatus", status),
			report.DiagnosticStructure("reason", text), report.DiagnosticStructure("rowId", row), run))
	scope := report.RuleStructure(jsonshape.StringGrammar(rowBody+`\.section_scope\.classification`), state, text,
		jsonshape.Tuple(report.DiagnosticStructure("classifiedRows", rows), environment, command, run))
	frontier := report.RuleStructure(jsonshape.StringGrammar(rowBody+`\.frontier\.non_claims`), state, text,
		jsonshape.Tuple(report.DiagnosticStructure("closeoutRow", row), environment, command, run))
	summary := jsonshape.Object(jsonshape.Required("blocked", count), jsonshape.Required("failed", count), jsonshape.Required("outOfScope", count),
		jsonshape.Required("passed", count), jsonshape.Required("readinessClaim", jsonshape.StringLiteral("classification_honesty_only")),
		jsonshape.Required("rowCount", count), jsonshape.Required("runIdentity", id))
	schema := report.Structure(1, reportKind, state, summary, jsonshape.Tuple(
		report.DiagnosticStructure("blockedRowIds", rows), report.DiagnosticStructure("outOfScopeRowIds", rows), report.DiagnosticStructure("passedRowIds", rows)),
		jsonshape.Array(jsonshape.OneOf(unique, classification, scope, frontier), 3)).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	nonClaims := jsonshape.Array(text, len(readinessCloseoutNonClaims)).JSONSchema()
	contains := make([]any, 0, len(readinessCloseoutNonClaims))
	for _, claim := range readinessCloseoutNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	nonClaims["allOf"], nonClaims["uniqueItems"], properties["nonClaims"] = contains, true, nonClaims
	schema["description"] = "Required header1 and fixed readiness-closeout identity; seven summary fields, three ordered root diagnostics and at least three rules. Rule diagnostics are four exact ordered tuples for unique rows, declared classification, section scope and frontier. Row/status IDs are normalized native grammars without an added length cap. Native Build owns rule/diagnostic ordering, row/reference closure, state and dependent counters: failed counts unique validation failures, not caller-declared failed classifications. Builtin/caller nonClaims are sorted and deduplicated. classification_honesty_only never becomes gate execution, receipt authentication, merge approval or deployment readiness."
	return schema
}
