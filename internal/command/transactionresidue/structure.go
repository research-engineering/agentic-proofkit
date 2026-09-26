package transactionresidue

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

var inspectionShape = jsonshape.DiscriminatedUnion("state",
	outputShape(inspectionKind, repositorytransaction.PreparationResidueAbsent, jsonshape.Null()),
	outputShape(inspectionKind, repositorytransaction.PreparationResidueEligible, observationShape()),
)

var relocationShape = outputShape(relocationKind, repositorytransaction.PreparationResidueQuarantined, observationShape())

func InspectionOutputStructure() map[string]any { return inspectionShape.JSONSchema() }
func RelocationOutputStructure() map[string]any { return relocationShape.JSONSchema() }

func observationShape() jsonshape.Shape {
	return jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)
}

func outputShape(kind, state string, observation jsonshape.Shape) jsonshape.Shape {
	claims := make([]jsonshape.Shape, len(nonClaims))
	for i, claim := range nonClaims {
		claims[i] = jsonshape.StringLiteral(claim)
	}
	return jsonshape.Object(
		jsonshape.Required("kind", jsonshape.StringLiteral(kind)),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("state", jsonshape.StringLiteral(state)),
		jsonshape.Required("observationId", observation),
		jsonshape.Required("nonClaims", jsonshape.Tuple(claims...)),
	)
}
