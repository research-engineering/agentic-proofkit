package report

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

// Structure owns JSONValue's carrier only. Commands supply the complete shapes
// of state, summary, diagnostics and rules; no opaque payload is introduced.
func Structure(version int64, kind string, state, summary, diagnostics, rules jsonshape.Shape) jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(version)),
		jsonshape.Required("reportKind", jsonshape.Enum(map[string]struct{}{kind: {}})),
		jsonshape.Required("reportId", jsonshape.String()),
		jsonshape.Required("state", state),
		jsonshape.Required("summary", summary),
		jsonshape.Required("diagnostics", diagnostics),
		jsonshape.Required("ruleResults", rules),
		jsonshape.Required("nonClaims", jsonshape.Array(jsonshape.String(), 0)),
	)
}
