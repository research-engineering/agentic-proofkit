package requirementdiff

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

var diffInputShape = jsonshape.Object(
	jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(3)),
	jsonshape.Required("diffId", jsonshape.String()),
	jsonshape.Required("baseContext", requirementcontext.SnapshotShape()),
	jsonshape.Required("currentContext", requirementcontext.SnapshotShape()),
	jsonshape.Optional("query", jsonshape.Nullable(jsonshape.Object(
		jsonshape.Optional("maxChanges", jsonshape.Nullable(jsonshape.IntegerMinimum(1))),
		jsonshape.Optional("ownerIds", jsonshape.Nullable(jsonshape.Array(jsonshape.String(), 0))),
		jsonshape.Optional("requirementIds", jsonshape.Nullable(jsonshape.Array(jsonshape.String(), 0))),
	))),
)

// InputStructure describes wire structure; native query admission additionally
// owns the maxChanges ceiling, ID uniqueness and snapshot semantic validity.
func InputStructure() map[string]any { return diffInputShape.JSONSchema() }
