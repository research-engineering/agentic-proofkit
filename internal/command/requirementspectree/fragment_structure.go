package requirementspectree

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

// FragmentShape allows empty selections and reference-filtered nodes. It is
// intentionally not a complete tree input and grants no tree authority.
func FragmentShape() jsonshape.Shape {
	fields := []jsonshape.Property{
		jsonshape.Required("authority", jsonshape.StringLiteral("lookup_fragment_only")),
		jsonshape.Required("projectionKind", jsonshape.StringLiteral("proofkit.requirement-spec-tree-fragment")),
		jsonshape.Required("sourceTreeId", jsonshape.String()),
		jsonshape.Required("rootNodeId", jsonshape.Nullable(jsonshape.String())),
		jsonshape.Required("nodes", jsonshape.BoundedArray(treeNodeShape(0), 0, maxSpecTreeNodes)),
	}
	for _, name := range []string{"schemaVersion", "callerAnnotations", "edges", "overlays"} {
		shape, ok := treeInputShape.Property(name)
		if !ok {
			panic("tree fragment references an absent owner field")
		}
		fields = append(fields, jsonshape.Required(name, shape))
	}
	return jsonshape.Object(fields...)
}
