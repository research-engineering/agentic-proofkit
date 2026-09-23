package requirementbinding

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

// The shared shape owns structure only. Canonical text, paths, uniqueness,
// sorting and semantic failed-report rules remain in their native owners.
var bindingInputShape = makeBindingInputShape()

func InputShape() jsonshape.Shape { return bindingInputShape }

func makeBindingInputShape() jsonshape.Shape {
	text := jsonshape.String()
	texts := jsonshape.Array(text, 0)
	requirement := jsonshape.Object(
		jsonshape.Required("claimLevel", jsonshape.Enum(claimLevels)),
		jsonshape.Required("nonClaims", texts),
		jsonshape.Required("ownerId", text),
		jsonshape.Required("proofState", jsonshape.Enum(proofStates)),
		jsonshape.Required("requirementId", text),
		jsonshape.Required("specPath", text),
	)
	selector := jsonshape.Object(
		jsonshape.Required("command", text),
		jsonshape.Required("selector", text),
	)
	binding := jsonshape.Object(
		jsonshape.Required("commandIds", texts),
		jsonshape.Required("environmentClasses", texts),
		jsonshape.Required("requirementId", text),
		jsonshape.Required("scenarioId", text),
		jsonshape.Required("witnessId", text),
		jsonshape.Required("witnessKind", jsonshape.Enum(witnessKinds)),
		jsonshape.Required("witnessPath", text),
		jsonshape.Optional("witnessSelectors", jsonshape.Nullable(jsonshape.Array(selector, 1))),
	)
	command := jsonshape.ExactlyOne(jsonshape.Object(
		jsonshape.Required("command", text),
		jsonshape.Required("commandId", text),
		jsonshape.Optional("environmentClass", text),
		jsonshape.Optional("environmentClasses", jsonshape.Array(text, 1)),
	), "environmentClass", "environmentClasses")
	selection := jsonshape.Nullable(jsonshape.Object(
		jsonshape.Optional("changedPaths", jsonshape.Nullable(texts)),
		jsonshape.Optional("ownerIds", jsonshape.Nullable(texts)),
		jsonshape.Optional("requirementIds", jsonshape.Nullable(texts)),
	))
	return jsonshape.Object(
		jsonshape.Required("bindingId", text),
		jsonshape.Required("bindings", jsonshape.Array(binding, 0)),
		jsonshape.Required("nonClaims", texts),
		jsonshape.Required("requirements", jsonshape.Array(requirement, 0)),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Optional("selection", selection),
		jsonshape.Required("witnessCommands", jsonshape.Array(command, 0)),
	)
}

// InputStructure projects only the shared structural boundary, not a complete
// native contract. Standard-schema success cannot replace Build admission.
func InputStructure() map[string]any {
	return bindingInputShape.JSONSchema()
}
