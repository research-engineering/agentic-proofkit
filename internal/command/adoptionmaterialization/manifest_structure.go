package adoptionmaterialization

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

var manifestShape = makeManifestShape()

func ManifestShape() jsonshape.Shape { return manifestShape }

func makeManifestShape() jsonshape.Shape {
	text := jsonshape.String()
	nonClaims := make([]jsonshape.Shape, len(manifestNonClaims))
	for i, value := range manifestNonClaims {
		nonClaims[i] = jsonshape.StringLiteral(value)
	}
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("manifestKind", jsonshape.StringLiteral(ManifestKind)),
		jsonshape.Required("authority", jsonshape.StringLiteral("routing_only")),
		jsonshape.Required("manifestId", text), jsonshape.Required("sourcePlanId", text),
		jsonshape.Required("materializationRequestId", text), jsonshape.Required("projectId", text),
		jsonshape.Required("nonClaims", jsonshape.Tuple(nonClaims...)),
		jsonshape.Required("routes", jsonshape.BoundedArray(jsonshape.Object(
			jsonshape.Required("artifactId", text), jsonshape.Required("artifactKind", jsonshape.Enum(artifactKindSet)),
			jsonshape.Required("path", text),
		), 3, repositoryRouteLimit())),
	)
}
