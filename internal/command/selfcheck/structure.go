package selfcheck

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func InputStructure() map[string]any {
	return map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"description": "Any strictly decoded JSON value is accepted: null, boolean, number, string, array or object. Object members are unrestricted, including any schemaVersion value. Contract schemaVersion is metadata, not an input header. Native decoding owns byte limits, duplicate-key rejection, number spelling and exactly-one-value framing; JSON Schema alone cannot prove these byte-level properties. The command classifies the input kind without exposing caller values or establishing native witness success.",
	}
}

func OutputStructure() map[string]any {
	kind := jsonshape.Enum(map[string]struct{}{"null": {}, "boolean": {}, "number": {}, "string": {}, "array": {}, "object": {}})
	schema := report.Structure(1, reportKind, jsonshape.StringLiteral("passed"),
		jsonshape.Object(jsonshape.Required("inputKind", kind)),
		jsonshape.Tuple(report.DiagnosticStructure("inputKind", kind)),
		jsonshape.Tuple(report.RuleStructure(jsonshape.StringLiteral(ruleID), jsonshape.StringLiteral("passed"),
			jsonshape.StringLiteral(ruleMessage), jsonshape.Tuple())),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = jsonshape.StringLiteral(reportKind).JSONSchema()
	properties["nonClaims"] = jsonshape.Tuple(jsonshape.StringLiteral(packageNonClaim), jsonshape.StringLiteral(witnessNonClaim)).JSONSchema()
	schema["description"] = "The sole successful report has one inputKind diagnostic, one passed rule with empty diagnostics, and two fixed ordered nonClaims. Summary and diagnostic kinds describe the same decoded input; native Build owns that equality. Input/flag errors emit stderr and no report. Structural validity does not prove native witness execution, repository state, merge approval or publication."
	return schema
}
