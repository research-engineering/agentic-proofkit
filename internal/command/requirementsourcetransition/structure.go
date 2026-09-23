package requirementsourcetransition

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

var transitionInputShape = inputStructure()
var transitionOutputShape = outputStructure()

func InputStructure() map[string]any  { return transitionInputShape.JSONSchema() }
func OutputStructure() map[string]any { return transitionOutputShape.JSONSchema() }

func inputStructure() jsonshape.Shape {
	source, err := requirementsourcecodec.InputShape(requirementsourcemodel.DefaultLimits())
	if err != nil {
		panic("invalid source structure for transition")
	}
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(inputSchemaVersion)),
		jsonshape.Required("transitionId", jsonshape.String()),
		jsonshape.Required("nonClaims", jsonshape.Array(jsonshape.String(), 0)),
		jsonshape.Required("previous", source),
		jsonshape.Required("next", source),
	)
}

func outputStructure() jsonshape.Shape {
	text, count := jsonshape.String(), jsonshape.IntegerMinimum(0)
	statuses := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	diagnostic := func(key, value jsonshape.Shape) jsonshape.Shape {
		return jsonshape.Object(jsonshape.Required("key", key), jsonshape.Required("value", value))
	}
	rule := func(id string, status, message jsonshape.Shape) jsonshape.Shape {
		return jsonshape.Object(jsonshape.Required("ruleId", jsonshape.StringLiteral(id)), jsonshape.Required("status", status), jsonshape.Required("message", message), jsonshape.Required("diagnostics", jsonshape.Array(diagnostic(text, text), 0)))
	}
	return report.Structure(outputSchemaVersion, reportKind, statuses,
		jsonshape.Object(
			jsonshape.Required("addedRequirementCount", jsonshape.Nullable(count)),
			jsonshape.Required("lifecycleChangedRequirementCount", jsonshape.Nullable(count)),
			jsonshape.Required("missingRequirementCount", jsonshape.Nullable(count)),
			jsonshape.Required("previousRequirementCount", count),
			jsonshape.Required("nextRequirementCount", count),
			jsonshape.Required("failureCount", count),
		),
		jsonshape.Tuple(diagnostic(jsonshape.StringLiteral("failures"), jsonshape.Array(text, 0)), diagnostic(jsonshape.StringLiteral("sourcePaths"), jsonshape.Tuple(text, text, text, text))),
		jsonshape.Tuple(
			rule(boundaryRuleID, statuses, jsonshape.StringLiteral(boundaryMessage)),
			rule(sourceRuleID, statuses, jsonshape.StringLiteral(sourceMessage)),
			rule(latticeRuleID, jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}, "skipped": {}}), jsonshape.Enum(map[string]struct{}{latticeMessage: {}, latticeSkippedMessage: {}})),
		),
	)
}
