package requirementsourceadmission

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var sourceOutputShape = sourceReportShape()

// OutputStructure shares emission's closed structural predicate. Semantic
// counts, diagnostic contents and rule status relations remain assessment-owned.
func OutputStructure() map[string]any { return sourceOutputShape.JSONSchema() }

func sourceReportShape() jsonshape.Shape {
	text := jsonshape.String()
	texts := jsonshape.Array(text, 0)
	count := jsonshape.IntegerMinimum(0)
	literal := func(value string) jsonshape.Shape { return jsonshape.Enum(map[string]struct{}{value: {}}) }
	diagnostic := func(key, value jsonshape.Shape) jsonshape.Shape {
		return jsonshape.Object(jsonshape.Required("key", key), jsonshape.Required("value", value))
	}
	rule := func(id string, status, message, diagnostics jsonshape.Shape) jsonshape.Shape {
		return jsonshape.Object(jsonshape.Required("ruleId", literal(id)), jsonshape.Required("status", status), jsonshape.Required("message", message), jsonshape.Required("diagnostics", diagnostics))
	}
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	return report.Structure(outputSchemaVersion, reportKind, status,
		jsonshape.Object(
			jsonshape.Required("activeRequirementCount", count),
			jsonshape.Required("blockingRequirementCount", count),
			jsonshape.Required("deferredRequirementCount", count),
			jsonshape.Required("failureCount", count),
			jsonshape.Required("requirementCount", count),
			jsonshape.Required("sourcePathCount", jsonshape.IntegerLiteral(3)),
		),
		jsonshape.Tuple(diagnostic(literal("failures"), texts), diagnostic(literal("sourcePaths"), texts)),
		jsonshape.Tuple(
			rule(boundaryRuleID, literal("passed"), literal(boundaryMessage), jsonshape.Tuple()),
			rule(lifecycleRuleID, status, jsonshape.Enum(map[string]struct{}{lifecyclePassedMessage: {}, lifecycleFailedMessage: {}}), jsonshape.Array(diagnostic(text, text), 0)),
			rule(shapeRuleID, literal("passed"), literal(shapeMessage), jsonshape.Tuple()),
		),
	)
}
