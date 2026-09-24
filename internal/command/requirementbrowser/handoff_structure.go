package requirementbrowser

import (
	"encoding/json"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

const resolvedRequirementCoordinateSpace = "resolved_requirement"

var anchorShape = jsonshape.Object(
	jsonshape.Required("anchorId", jsonshape.String()),
	jsonshape.Required("coordinateSpace", jsonshape.StringLiteral(resolvedRequirementCoordinateSpace)),
	jsonshape.Required("jsonPointer", jsonshape.String()),
	jsonshape.Required("requirementId", jsonshape.String()),
	jsonshape.Required("sourceId", jsonshape.String()),
	jsonshape.Required("sourceDigest", jsonshape.String()),
)

// OutputHandoffClauses declares only the changed one-shot anchor child.
// Complete packet and browser-session admission remain native obligations.
func OutputHandoffClauses() []any {
	return []any{map[string]any{
		"appliesWhen": "03-one-shot-submitted", "packetSchemaVersion": json.Number("2"),
		"pathSegments": []any{"annotations", "*", "anchor"},
		"anchorSchema": anchorShape.JSONSchema(),
	}}
}
