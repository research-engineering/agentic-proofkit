package report

type Record struct {
	SchemaVersion int
	ReportKind    string
	ReportID      string
	State         string
	Summary       map[string]any
	Diagnostics   []Diagnostic
	RuleResults   []RuleResult
	NonClaims     []any
}

type Diagnostic struct {
	Key   string
	Value any
}

type RuleResult struct {
	RuleID      string
	Status      string
	Message     string
	Diagnostics []Diagnostic
}

func (record Record) JSONValue() map[string]any {
	diagnostics := make([]any, 0, len(record.Diagnostics))
	for _, diagnostic := range record.Diagnostics {
		diagnostics = append(diagnostics, map[string]any{
			"key":   diagnostic.Key,
			"value": diagnostic.Value,
		})
	}
	ruleResults := make([]any, 0, len(record.RuleResults))
	for _, rule := range record.RuleResults {
		diagnostics := make([]any, 0, len(rule.Diagnostics))
		for _, diagnostic := range rule.Diagnostics {
			diagnostics = append(diagnostics, map[string]any{
				"key":   diagnostic.Key,
				"value": diagnostic.Value,
			})
		}
		ruleResults = append(ruleResults, map[string]any{
			"diagnostics": diagnostics,
			"message":     rule.Message,
			"ruleId":      rule.RuleID,
			"status":      rule.Status,
		})
	}
	return map[string]any{
		"diagnostics":   diagnostics,
		"nonClaims":     record.NonClaims,
		"reportId":      record.ReportID,
		"reportKind":    record.ReportKind,
		"ruleResults":   ruleResults,
		"schemaVersion": record.SchemaVersion,
		"state":         record.State,
		"summary":       record.Summary,
	}
}
