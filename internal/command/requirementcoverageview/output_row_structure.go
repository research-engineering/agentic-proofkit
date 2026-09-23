package requirementcoverageview

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
)

func coverageRequirementShape(mode string) jsonshape.Shape {
	text, texts := jsonshape.String(), jsonshape.Array(jsonshape.String(), 0)
	atomic := requirementsourceadmission.RequirementShape()
	field := func(name string) jsonshape.Shape { return coverageShapeProperty(atomic, name) }
	fields := []jsonshape.Property{
		jsonshape.Required("requirementId", field("requirementId")), jsonshape.Required("ownerId", field("ownerId")),
		jsonshape.Required("invariant", field("invariant")), jsonshape.Required("claimLevel", field("claimLevel")),
		jsonshape.Required("lifecycleState", coverageShapeProperty(field("lifecycle"), "state")),
		jsonshape.Required("specPath", text), jsonshape.Required("scenarioCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("tests", jsonshape.Array(coverageTestShape(), 0)),
		jsonshape.Required("coverageState", coverageStateShape("requirementCoverage")),
		jsonshape.Required("evidenceClass", jsonshape.OneOf(testevidenceinventory.EvidenceClassShape(), jsonshape.StringLiteral(""))),
		jsonshape.Required("scenarios", jsonshape.Array(coverageScenarioShape(mode), 0)),
	}
	for _, name := range []string{"nonClaims", "nonClaimRefs", "externalNonClaimRefs", "sharedPremises"} {
		// These are resolved projection arrays, without source encoding bounds.
		fields = append(fields, jsonshape.Required(name, texts))
	}
	for _, name := range []string{"commandIds", "environmentClasses", "failures", "testIds", "verifyCommands"} {
		fields = append(fields, jsonshape.Required(name, texts))
	}
	if mode == "compact" {
		fields = append(fields, jsonshape.Required("declaredWitnessRoutes", jsonshape.Array(coverageWitnessRouteShape(), 0)))
	} else {
		fields = append(fields,
			jsonshape.Required("proofState", jsonshape.OneOf(jsonshape.StringLiteral(""), jsonshape.Enum(proofvocab.RequirementProofStateSet()))),
			jsonshape.Required("witnessRefs", texts))
	}
	return jsonshape.Object(fields...)
}

func coverageOwnerInvariantShape() jsonshape.Shape {
	text, texts := jsonshape.String(), jsonshape.Array(jsonshape.String(), 0)
	return jsonshape.Object(
		jsonshape.Required("ownerInvariantId", text), jsonshape.Required("ownerId", text),
		jsonshape.Required("sourcePath", text), jsonshape.Required("summary", text),
		jsonshape.Required("coverageState", coverageStateShape("ownerInvariantCoverage")),
		jsonshape.Required("evidenceClass", jsonshape.OneOf(testevidenceinventory.EvidenceClassShape(), jsonshape.StringLiteral(""))),
		jsonshape.Required("nonClaims", texts), jsonshape.Required("testIds", texts), jsonshape.Required("warnings", texts),
		jsonshape.Required("tests", jsonshape.Array(coverageTestShape(), 0)),
	)
}

func coverageCommandShape() jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("commandId", jsonshape.String()),
		jsonshape.Required("coverageState", coverageStateShape("commandCoverage")),
		jsonshape.Required("failures", jsonshape.Array(jsonshape.String(), 0)),
		jsonshape.Required("testIds", jsonshape.Array(jsonshape.String(), 0)),
		jsonshape.Required("tests", jsonshape.Array(coverageTestShape(), 0)),
	)
}

func coverageStateShape(rowsKey string) jsonshape.Shape {
	states := map[string]struct{}{}
	if rowsKey == "commandCoverage" {
		states[missingCommandCoverageState] = struct{}{}
	}
	for _, descriptor := range coverageStateDescriptors {
		switch {
		case rowsKey == "requirementCoverage" && descriptor.requirementAdmissible,
			rowsKey == "ownerInvariantCoverage" && descriptor.ownerInvariantAdmissible:
			states[descriptor.requirementState] = struct{}{}
		case rowsKey == "commandCoverage" && descriptor.commandState != "":
			states[descriptor.commandState] = struct{}{}
		}
	}
	return jsonshape.Enum(states)
}

func coverageTestShape() jsonshape.Shape {
	text, texts := jsonshape.String(), jsonshape.Array(jsonshape.String(), 0)
	fields := []jsonshape.Property{
		jsonshape.Required("evidenceClass", testevidenceinventory.EvidenceClassShape()),
		jsonshape.Required("qualityFindings", jsonshape.Array(testevidenceinventory.QualityFindingShape(), 0)),
	}
	for _, name := range []string{"commandRefs", "nonClaims", "ownerInvariantRefs", "requirementRefs", "supersedes", "witnessRefs"} {
		fields = append(fields, jsonshape.Required(name, texts))
	}
	for _, name := range []string{"dominanceGroup", "expectedPublicOutcome", "falsifierId", "negativeCaseId", "oracleId", "oracleKind", "oracleSummary", "ownerId", "selector", "sourcePath", "supersessionDeclarationRef", "testId", "wrongImplementationClassId"} {
		fields = append(fields, jsonshape.Required(name, text))
	}
	return jsonshape.Object(fields...)
}

func coverageScenarioShape(mode string) jsonshape.Shape {
	text, texts := jsonshape.String(), jsonshape.Array(jsonshape.String(), 0)
	fields := []jsonshape.Property{
		jsonshape.Required("scenarioId", text), jsonshape.Required("environmentClasses", texts), jsonshape.Required("verifyCommands", texts),
	}
	if mode == "compact" {
		for _, name := range []string{"bindingRecordId", "requirementId", "surfaceId"} {
			fields = append(fields, jsonshape.Required(name, text))
		}
		fields = append(fields, jsonshape.Required("bindingVerifyCommands", texts), jsonshape.Required("requiredEnvironmentClasses", texts),
			jsonshape.Required("declaredWitnessRoutes", jsonshape.Array(coverageWitnessRouteShape(), 0)))
	} else {
		fields = append(fields, jsonshape.Required("commandIds", texts))
		for _, name := range []string{"witnessId", "witnessKind", "witnessPath"} {
			fields = append(fields, jsonshape.Required(name, text))
		}
	}
	return jsonshape.Object(fields...)
}

func coverageWitnessRouteShape() jsonshape.Shape {
	text, texts := jsonshape.String(), jsonshape.Array(jsonshape.String(), 0)
	fields := []jsonshape.Property{
		jsonshape.Required("environmentClasses", texts), jsonshape.Required("verifyCommands", texts),
		jsonshape.Required("resolutionOrderIndex", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("role", jsonshape.Enum(map[string]struct{}{
			compactproofcontract.FalsificationWitnessRole: {}, compactproofcontract.PositiveWitnessRole: {},
		})),
	}
	for _, name := range []string{"bindingRecordId", "requirementId", "scenarioId", "selector", "surfaceId", "witnessRouteId"} {
		fields = append(fields, jsonshape.Required(name, text))
	}
	return jsonshape.Object(fields...)
}

func coverageShapeProperty(parent jsonshape.Shape, name string) jsonshape.Shape {
	child, ok := parent.Property(name)
	if !ok {
		panic("coverage projection references an absent owner property")
	}
	return child
}
