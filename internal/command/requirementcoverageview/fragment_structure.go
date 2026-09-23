package requirementcoverageview

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func FragmentShape() jsonshape.Shape {
	text := jsonshape.String()
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)),
		jsonshape.Required("authority", jsonshape.StringLiteral("lookup_fragment_only")),
		jsonshape.Required("viewKind", jsonshape.StringLiteral("proofkit.requirement-coverage-fragment")),
		jsonshape.Required("sourceId", text), jsonshape.Required("sourceViewInputId", text),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Required("nonClaimDefinitions", requirementsourceadmission.NonClaimDefinitionsShape()),
		jsonshape.Required("requirementCoverageCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("requirementCoverage", jsonshape.Array(jsonshape.OneOf(coverageRequirementShape("compact"), coverageRequirementShape("structured")), 0)),
	)
}
