package requirementbinding

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

// SelectionFragmentShape retains bindings as lookup facts, not executable proof.
func SelectionFragmentShape() jsonshape.Shape {
	fields := []jsonshape.Property{
		jsonshape.Required("authority", jsonshape.StringLiteral("lookup_fragment_only")),
		jsonshape.Required("projectionKind", jsonshape.StringLiteral("proofkit.requirement-binding-fragment")),
		jsonshape.Required("sourceBindingId", jsonshape.String()),
	}
	for _, name := range []string{"schemaVersion", "requirements", "bindings", "witnessCommands", "nonClaims"} {
		shape, ok := bindingInputShape.Property(name)
		if !ok {
			panic("binding fragment references an absent owner field")
		}
		fields = append(fields, jsonshape.Required(name, shape))
	}
	texts := jsonshape.Array(jsonshape.String(), 0)
	fields = append(fields, jsonshape.Required("selection", jsonshape.Object(
		jsonshape.Required("changedPaths", texts), jsonshape.Required("ownerIds", texts), jsonshape.Required("requirementIds", texts),
	)))
	return jsonshape.Object(fields...)
}
