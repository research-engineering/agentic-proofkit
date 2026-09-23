package requirementcontext

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

var sliceProfiles = map[string]struct{}{"coverage": {}, "proof": {}, "review": {}, "routing": {}, "specification": {}}

var sliceQueryShape = jsonshape.Object(
	jsonshape.Required("profile", jsonshape.Enum(sliceProfiles)),
	jsonshape.Optional("nodeIds", jsonshape.Nullable(jsonshape.Array(jsonshape.String(), 0))),
	jsonshape.Optional("ownerIds", jsonshape.Nullable(jsonshape.Array(jsonshape.String(), 0))),
	jsonshape.Optional("requirementIds", jsonshape.Nullable(jsonshape.Array(jsonshape.String(), 0))),
	jsonshape.Optional("lifecycleStates", jsonshape.Nullable(jsonshape.Array(requirementsourceadmission.LifecycleStateShape(), 0))),
	jsonshape.Optional("maxNodes", jsonshape.Nullable(jsonshape.IntegerMinimum(1))),
	jsonshape.Optional("maxRequirements", jsonshape.Nullable(jsonshape.IntegerMinimum(1))),
	// Depth retains native non-negative integer parsing, including the -0 token.
	jsonshape.Optional("maxDepth", jsonshape.Nullable(jsonshape.Number())),
)

var sliceInputShape = jsonshape.Object(
	jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)),
	jsonshape.Required("sliceId", jsonshape.String()),
	jsonshape.Required("context", SnapshotShape()),
	jsonshape.Required("query", sliceQueryShape),
)

func SliceInputStructure() map[string]any { return sliceInputShape.JSONSchema() }
