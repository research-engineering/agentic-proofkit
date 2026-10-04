package testevidenceinventory

import (
	"regexp"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

// InventoryInputShape covers native inventory admission, not projection flags.
func InventoryInputShape() jsonshape.Shape {
	bare := jsonshape.DiscriminatedUnion("authority", DirectInputShape(), SourceSetInputShape())
	return jsonshape.OneOf(bare, wrappedInventoryShapeOf(bare))
}

// DirectBoundaryShape includes the wrapper accepted by EvaluateDirect.
func DirectBoundaryShape() jsonshape.Shape {
	return jsonshape.OneOf(DirectInputShape(), wrappedInventoryShapeOf(DirectInputShape()))
}

func WrappedInputShape() jsonshape.Shape {
	return wrappedInventoryShapeOf(jsonshape.DiscriminatedUnion("authority", DirectInputShape(), SourceSetInputShape()))
}

func wrappedInventoryShapeOf(inventory jsonshape.Shape) jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("schema", jsonshape.StringLiteral(wrappedInventorySchema)),
		jsonshape.Required("inventory", inventory),
	)
}

func SourceSetInputShape() jsonshape.Shape {
	text := jsonshape.String()
	columns := make([]jsonshape.Shape, len(sourceSetColumns))
	for i, name := range sourceSetColumns {
		// Native admission trims each header before comparing its fixed value.
		columns[i] = jsonshape.WhitespaceStringGrammar(func(space string) string {
			return "[" + space + "]*" + regexp.QuoteMeta(name) + "[" + space + "]*"
		})
	}
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("authority", jsonshape.StringLiteral(sourceSetAuthority)),
		jsonshape.Required("inventoryId", text),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Required("sourceColumns", jsonshape.Tuple(columns...)),
		jsonshape.Required("sources", jsonshape.Array(sourceRowShape(), 1)),
		jsonshape.Required("sourceTexts", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("path", text), jsonshape.Required("text", text),
		), 1)),
	)
}

func sourceRowShape() jsonshape.Shape {
	return jsonshape.Tuple(jsonshape.String(), jsonshape.String(),
		jsonshape.StringGrammar(`[a-f0-9]{64}`), jsonshape.Enum(sourceRoles),
		jsonshape.Array(jsonshape.String(), 1))
}

func DiscoveryInputShape() jsonshape.Shape {
	text := jsonshape.String()
	texts := jsonshape.Array(text, 0)
	nonClaims := jsonshape.Optional("nonClaims", jsonshape.Nullable(texts))
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("authority", jsonshape.StringLiteral(discoveryAuthority)),
		jsonshape.Required("draftId", text), nonClaims,
		jsonshape.Required("repository", jsonshape.Object(jsonshape.Required("repositoryId", text), nonClaims)),
		jsonshape.Required("runner", jsonshape.Object(
			jsonshape.Required("runnerId", text), jsonshape.Required("runnerKind", jsonshape.Enum(runnerKindSet)),
			jsonshape.Required("commandRef", text), jsonshape.Required("environmentClass", text), nonClaims,
		)),
		jsonshape.Required("discoveredTests", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("testId", text), jsonshape.Required("ownerId", text),
			jsonshape.Required("selector", text), jsonshape.Required("sourcePath", text), jsonshape.Required("title", text),
			jsonshape.Required("candidateRequirementRefs", texts), jsonshape.Required("ownerInvariantRefs", texts),
			jsonshape.Required("oracleSignals", jsonshape.Array(jsonshape.Enum(oracleSignalSet), 0)),
			jsonshape.Required("selectorSignals", jsonshape.Array(jsonshape.Enum(selectorSignalSet), 0)), nonClaims,
		), 1)),
	)
}
