package requirementdiff

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

var diffOutputShape = makeDiffOutputShape()

func OutputStructure() map[string]any { return diffOutputShape.JSONSchema() }

func makeDiffOutputShape() jsonshape.Shape {
	text, value := jsonshape.String(), requirementsourceadmission.ComparisonValueShape()
	change := jsonshape.Object(
		jsonshape.Required("changeId", text), jsonshape.Required("changeClass", jsonshape.Enum(changeClasses)),
		jsonshape.Required("entityId", text), jsonshape.Required("entityKind", jsonshape.StringLiteral("requirement")),
		jsonshape.Required("jsonPointer", text),
		jsonshape.Required("before", value), jsonshape.Required("after", value),
		jsonshape.Required("baseSourceDigest", jsonshape.Nullable(text)), jsonshape.Required("currentSourceDigest", jsonshape.Nullable(text)),
	)
	denials := make([]jsonshape.Shape, len(nonClaims))
	for i, value := range nonClaims {
		denials[i] = jsonshape.StringLiteral(value)
	}
	coverage := jsonshape.Enum(map[string]struct{}{"all": {}, "none": {}, "partial": {}})
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(3)),
		jsonshape.Required("diffKind", jsonshape.StringLiteral("proofkit.requirement-semantic-diff")),
		jsonshape.Required("diffId", text), jsonshape.Required("baseSnapshotId", text), jsonshape.Required("currentSnapshotId", text),
		jsonshape.Required("baseExpectedDigestCoverage", coverage), jsonshape.Required("currentExpectedDigestCoverage", coverage),
		jsonshape.Required("changes", jsonshape.BoundedArray(change, 0, maxChanges)),
		jsonshape.Required("changeCount", jsonshape.IntegerMinimum(0)), jsonshape.Required("nonClaims", jsonshape.Tuple(denials...)),
	)
}
