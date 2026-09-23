package requirementcontext

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

var catalogInputShape = jsonshape.Object(
	jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)),
	jsonshape.Required("catalogId", jsonshape.String()),
	jsonshape.Required("specTree", catalogEntryShape(false)),
	jsonshape.Required("requirementSources", jsonshape.Array(catalogEntryShape(true), 1)),
	jsonshape.Optional("coverage", jsonshape.Nullable(catalogEntryShape(false))),
	jsonshape.Optional("proofBinding", jsonshape.Nullable(catalogEntryShape(false))),
)

// CatalogInputStructure describes file references, not the referenced sources.
// Path identity, uniqueness, digest validity and file reads remain native policy.
func CatalogInputStructure() map[string]any { return catalogInputShape.JSONSchema() }

func catalogEntryShape(requirementSource bool) jsonshape.Shape {
	fields := []jsonshape.Property{
		jsonshape.Required("path", jsonshape.String()),
		jsonshape.Optional("sourceRef", jsonshape.Nullable(jsonshape.String())),
		jsonshape.Optional("expectedSourceDigest", jsonshape.Nullable(jsonshape.String())),
	}
	if requirementSource {
		fields = append(fields, jsonshape.Required("nodeId", jsonshape.String()))
	} else {
		fields = append(fields, jsonshape.Optional("nodeId", jsonshape.Null()))
	}
	return jsonshape.Object(fields...)
}
