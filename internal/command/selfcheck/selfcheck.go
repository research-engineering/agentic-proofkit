package selfcheck

import "github.com/research-engineering/agentic-proofkit/internal/kernel/report"

const (
	reportKind      = "proofkit.go-runtime.self-check"
	ruleID          = "proofkit.go-runtime.self-check.explicit-input"
	ruleMessage     = "Go bootstrap runtime parsed explicit JSON input and emitted a deterministic report."
	packageNonClaim = "Go self-check does not replace the full package gate."
	witnessNonClaim = "Go self-check does not execute native witnesses, read repository state, approve merge, or publish artifacts."
)

// Build classifies an already decoded JSON value without exposing its contents.
func Build(input any) report.Record {
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      reportKind,
		State:         "passed",
		Summary:       map[string]any{"inputKind": jsonKind(input)},
		Diagnostics:   []report.Diagnostic{{Key: "inputKind", Value: jsonKind(input)}},
		RuleResults:   []report.RuleResult{{RuleID: ruleID, Status: "passed", Message: ruleMessage}},
		NonClaims:     []any{packageNonClaim, witnessNonClaim},
	}
}

func jsonKind(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "number"
	}
}
