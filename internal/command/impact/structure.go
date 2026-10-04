package impact

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func impactIdentifier() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

func impactDigest(input bool) jsonshape.Shape {
	if !input {
		return jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)
	}
	return jsonshape.WhitespaceStringGrammar(func(class string) string {
		space := `[` + class + `]*`
		return space + `sha256:` + space + `[0-9a-f]{64}` + space
	})
}

func witnessRouteShape(input, declared bool) jsonshape.Shape {
	fields := []jsonshape.Property{
		jsonshape.Required("bindingRecordId", impactDigest(input)),
		jsonshape.Required("resolutionOrderIndex", jsonshape.IntegerRange(0, compactproofcontract.MaxResolutionOrderIndex)),
		jsonshape.Required("role", jsonshape.Enum(witnessRoles)), jsonshape.Required("selector", jsonshape.NonBlankString()),
		jsonshape.Required("witnessRouteId", impactDigest(input)),
	}
	if declared {
		fields = append(fields, jsonshape.Required("environmentClasses", jsonshape.Array(impactIdentifier(), 0)),
			jsonshape.Required("verifyCommands", jsonshape.Array(jsonshape.NonBlankString(), 0)))
	}
	return jsonshape.Object(fields...)
}

func obligationShape(input bool, extra ...jsonshape.Property) jsonshape.Shape {
	id, text := impactIdentifier(), jsonshape.NonBlankString()
	fields := []jsonshape.Property{
		jsonshape.Required("bindingRecordId", impactDigest(input)), jsonshape.Required("blockingStatus", id),
		jsonshape.Required("commands", jsonshape.Array(text, 1)), jsonshape.Required("declaredMutationResistanceClaimId", id),
		jsonshape.Required("declaredWitnessRoutes", jsonshape.BoundedArray(witnessRouteShape(input, true), 2, 2)),
		jsonshape.Required("preconditioned", jsonshape.Boolean()), jsonshape.Required("requirementId", id),
		jsonshape.Required("requiredEnvironmentClasses", jsonshape.Array(text, 1)),
		jsonshape.Required("scenarioId", text), jsonshape.Required("surfaceId", id),
	}
	return jsonshape.Object(append(fields, extra...)...)
}

func impactIdentityFields() []jsonshape.Property {
	text := jsonshape.NonBlankString()
	return []jsonshape.Property{
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)),
		jsonshape.Required("baseCommit", text), jsonshape.Required("baseRef", text),
		jsonshape.Required("headCommit", jsonshape.Nullable(text)), jsonshape.Required("headRef", text),
	}
}

func InputStructure() map[string]any {
	text := jsonshape.NonBlankString()
	texts := jsonshape.Array(text, 0)
	fields := append(impactIdentityFields(),
		jsonshape.Required("changedPaths", texts), jsonshape.Required("changedRequirementIds", jsonshape.Array(impactIdentifier(), 0)),
		jsonshape.Required("changedBindingRecordIds", jsonshape.Array(impactDigest(true), 0)),
		jsonshape.Required("changedWitnessPathCoverage", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("path", text), jsonshape.Required("routes", jsonshape.Array(witnessRouteShape(true, false), 1))), 0)),
		jsonshape.Required("generatedArtifactRules", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("generatedPath", text), jsonshape.Required("sourcePathPatterns", texts)), 0)),
		jsonshape.Required("ignoredProofLikePaths", texts), jsonshape.Required("proofLikePaths", texts),
		jsonshape.Required("obligationCatalog", jsonshape.Array(obligationShape(true), 0)),
		jsonshape.Required("preexistingFailures", texts), jsonshape.Optional("nonClaims", jsonshape.Nullable(texts)),
		jsonshape.Optional("unboundProofChangeRationale", text),
	)
	schema := jsonshape.Object(fields...).JSONSchema()
	schema["description"] = "Native admission normalizes display text and digest whitespace, sorts selected scalar arrays and rejects normalized duplicates except preexistingFailures. It owns path/pattern/selector syntax, privacy, canonical numeric tokens, scenario scope, content-derived binding/route identities, unique catalogs, route-ID ordering, one declared route per role and command/environment inclusion. blockingStatus is an arbitrary admitted RuleID; requiredEnvironmentClasses contains nonempty text. headCommit is required and nullable; nonClaims admits absence/null/empty. Generated-rule source patterns may be empty. Native evaluation, not structural admission, owns unbound-proof and generated-mirror failures. No agent-envelope mode exists."
	return schema
}

func OutputStructure() map[string]any {
	text := jsonshape.NonBlankString()
	fields := append(impactIdentityFields(),
		jsonshape.Required("changedPaths", jsonshape.Array(text, 0)),
		jsonshape.Required("changedRequirementIds", jsonshape.Array(impactIdentifier(), 0)),
		jsonshape.Required("failures", jsonshape.Array(text, 0)),
		jsonshape.Required("impactState", jsonshape.Enum(map[string]struct{}{stateOK: {}, stateFailed: {}})),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Required("obligations", jsonshape.Array(obligationShape(false,
			jsonshape.Required("changeReasons", jsonshape.Array(jsonshape.Enum(map[string]struct{}{
				requirementChanged: {}, bindingChanged: {}, witnessChanged: {},
			}), 1)), jsonshape.Required("witnessRoutes", jsonshape.Array(witnessRouteShape(false, false), 0))), 0)),
		jsonshape.Required("unboundProofChanges", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("path", text), jsonshape.Required("rationale", jsonshape.String())), 0)),
	)
	schema := jsonshape.Object(fields...).JSONSchema()
	schema["description"] = "Native evaluation owns failure/state/exit equality, selected obligations, reference joins, sorted unique failures and paths, content-derived identities and normalized values. Changed paths or requirements can be empty, and an obligation may have no changed witness routes. Declared route order is witnessRouteId order, not fixed role order. Unbound rationale can be empty on failed reports. This is caller-owned impact information, not execution, freshness or merge authority. Admission errors emit no report."
	return schema
}
