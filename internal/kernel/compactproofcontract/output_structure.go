package compactproofcontract

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func outputIdentifier() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

func outputDigest() jsonshape.Shape { return jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`) }

func bindingOutputProperties() []jsonshape.Property {
	id := outputIdentifier()
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return []jsonshape.Property{
		jsonshape.Required("bindingRecordId", outputDigest()), jsonshape.Required("blockingStatus", id),
		jsonshape.Required("declaredMutationResistanceClaimId", id), jsonshape.Required("invariantRole", id),
		jsonshape.Required("ownedInvariant", id), jsonshape.Required("requiredEnvironmentClasses", jsonshape.Array(id, 0)),
		jsonshape.Required("requirementId", id), jsonshape.Required("scenarioId", text), jsonshape.Required("surfaceId", id),
		jsonshape.Required("verifyCommands", jsonshape.Array(text, 0)),
	}
}

func witnessOutputStructure(role jsonshape.Shape, commandField string, extra ...jsonshape.Property) jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return jsonshape.Object(append([]jsonshape.Property{
		jsonshape.Required("environmentClasses", jsonshape.Array(outputIdentifier(), 0)),
		jsonshape.Required("resolutionOrderIndex", jsonshape.IntegerRange(0, MaxResolutionOrderIndex)),
		jsonshape.Required("role", role), jsonshape.Required("selector", text),
		jsonshape.Required(commandField, jsonshape.Array(text, 0)), jsonshape.Required("witnessRouteId", outputDigest()),
	}, extra...)...)
}

func ResolverOutputStructure() map[string]any {
	id, hash := outputIdentifier(), outputDigest()
	text := jsonshape.StringGrammar(`[\s\S]+`)
	ids, hashes := jsonshape.Array(id, 0), jsonshape.Array(hash, 0)
	falsification, positive := jsonshape.StringLiteral(FalsificationWitnessRole), jsonshape.StringLiteral(PositiveWitnessRole)
	bindings := jsonshape.Object(append(bindingOutputProperties(),
		jsonshape.Required("preconditioned", jsonshape.Boolean()),
		jsonshape.Required("testWitnesses", jsonshape.Object(
			jsonshape.Required("falsification", witnessOutputStructure(falsification, "verifyCommandRefs")),
			jsonshape.Required("positive", witnessOutputStructure(positive, "verifyCommandRefs")))),
	)...)
	declarationBindings := jsonshape.Object(append(bindingOutputProperties(), jsonshape.Required("witnessRefs", jsonshape.Tuple(
		witnessOutputStructure(falsification, "verifyCommands"), witnessOutputStructure(positive, "verifyCommands"))))...)
	declaration := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)), jsonshape.Required("contractId", text),
		jsonshape.Required("declarationKind", jsonshape.StringLiteral("proofkit.requirement-proof-route-declaration")),
		jsonshape.Required("bindings", jsonshape.Array(declarationBindings, 0)),
		jsonshape.Required("surfaces", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("preconditionedEnvironmentClasses", ids), jsonshape.Required("requiredEnvironmentClasses", ids), jsonshape.Required("surfaceId", id)), 0)),
	)
	route := witnessOutputStructure(jsonshape.Enum(map[string]struct{}{PositiveWitnessRole: {}, FalsificationWitnessRole: {}}), "verifyCommandRefs",
		jsonshape.Required("bindingRecordId", hash), jsonshape.Required("requirementId", id),
		jsonshape.Required("scenarioId", text), jsonshape.Required("surfaceId", id))
	schema := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)),
		jsonshape.Required("projectionKind", jsonshape.StringLiteral("proofkit.requirement-proof-route-resolver")),
		jsonshape.Required("contractId", text), jsonshape.Required("nonClaims", jsonshape.Array(text, 0)),
		jsonshape.Required("bindings", jsonshape.Array(bindings, 0)), jsonshape.Required("witnessRoutes", jsonshape.Array(route, 0)),
		jsonshape.Required("conformanceProofContract", declaration),
		jsonshape.Required("localEnvironmentPolicy", jsonshape.Object(
			jsonshape.Required("authority", jsonshape.StringLiteral("caller_provided")), jsonshape.Required("localEnvironmentClasses", ids))),
		jsonshape.Required("commands", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("environmentClasses", ids), jsonshape.Required("bindingRecordIds", jsonshape.Array(hash, 1)),
			jsonshape.Required("verifyCommandRef", text), jsonshape.Required("witnessRouteIds", hashes)), 0)),
		jsonshape.Required("environmentClasses", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("bindingRecordIds", hashes), jsonshape.Required("environmentClass", id),
			jsonshape.Required("surfaceIds", jsonshape.Array(id, 1)), jsonshape.Required("witnessRouteIds", hashes)), 0)),
		jsonshape.Required("surfaces", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("bindingRecordIds", hashes), jsonshape.Required("requirementIds", ids), jsonshape.Required("surfaceId", id)), 0)),
		jsonshape.Required("scenarios", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("bindingRecordId", hash), jsonshape.Required("requirementId", id), jsonshape.Required("scenarioId", text), jsonshape.Required("surfaceId", id)), 0)),
	).JSONSchema()
	schema["description"] = "All fields are present and non-null. Native admission owns canonical identifiers and integer tokens, scoped scenario and repo-relative selector grammars, display-only commands, privacy and references. Binding and route IDs are SHA-256 references derived by the v2 identity domains; shape alone does not prove their contents. Each binding has both witness roles; declaration witnessRefs order is falsification then positive, independent of resolutionOrderIndex. Native derivation owns sortedness, joins, counts and preconditioned evaluation under caller-provided localEnvironmentClasses. Empty contracts, command/environment lists, surface-only environments and binding-only commands are supported. There is no failed-report variant; admission errors emit no resolver. Lookup facts do not execute tests, admit evidence freshness or grant merge authority."
	return schema
}
