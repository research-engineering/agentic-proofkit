package requirementauthoringplan

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

const (
	inputSchemaVersion      = 2
	outputSchemaVersion     = 3
	omittedCandidateMessage = "candidate requirement payload is omitted until candidate source and transition admission pass"
)

var authoringInputShape, authoringOutputShape = authoringStructures()

func InputStructure() map[string]any  { return authoringInputShape.JSONSchema() }
func OutputStructure() map[string]any { return authoringOutputShape.JSONSchema() }

func authoringStructures() (jsonshape.Shape, jsonshape.Shape) {
	source, err := requirementsourcecodec.InputShape(requirementsourcemodel.DefaultLimits())
	if err != nil {
		panic("invalid source shape for authoring")
	}
	text, count := jsonshape.String(), jsonshape.IntegerMinimum(0)
	texts := jsonshape.Array(text, 0)
	states := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	stepStates := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}, "skipped": {}})
	input := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(inputSchemaVersion)),
		jsonshape.Required("authoringPlanId", text), jsonshape.Required("mode", jsonshape.Enum(modeSet)),
		jsonshape.Required("nonClaims", texts),
		jsonshape.Required("currentRequirementSource", source), jsonshape.Required("candidateRequirementSource", source),
		jsonshape.Required("authoringRefs", jsonshape.Array(authoringReferenceShape(false), 1)),
		jsonshape.Required("candidateUpdates", jsonshape.Array(candidateStructure(false), 0)),
	)
	preview := jsonshape.Object(
		jsonshape.Required("authority", jsonshape.StringLiteral("candidate_only")),
		jsonshape.Required("candidateOnly", jsonshape.BooleanLiteral(true)),
		jsonshape.Required("ownerReviewRequired", jsonshape.BooleanLiteral(true)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Required("requirementSourcePreview", source),
		jsonshape.Required("sourceAdmissionState", jsonshape.StringLiteral("passed")),
		jsonshape.Required("transitionAdmissionState", jsonshape.StringLiteral("passed")),
	)
	rule := func(id string, status jsonshape.Shape) jsonshape.Shape {
		return jsonshape.Object(jsonshape.Required("ruleId", jsonshape.StringLiteral(planKind+"."+id)), jsonshape.Required("status", status), jsonshape.Required("message", text), jsonshape.Required("diagnostics", jsonshape.Array(jsonshape.Object(jsonshape.Required("key", text), jsonshape.Required("value", text)), 0)))
	}
	precondition := jsonshape.Object(jsonshape.Required("preconditionId", text), jsonshape.Required("kind", jsonshape.Enum(map[string]struct{}{"owner_review": {}, "materialization": {}, "proof_binding": {}, "native_witness": {}})), jsonshape.Required("description", text), jsonshape.Required("ref", text))
	output := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(outputSchemaVersion)), jsonshape.Required("planKind", jsonshape.StringLiteral(planKind)),
		jsonshape.Required("authoringPlanId", text), jsonshape.Required("mode", jsonshape.Enum(modeSet)), jsonshape.Required("state", states),
		jsonshape.Required("authoringRefs", jsonshape.Array(authoringReferenceShape(true), 1)),
		jsonshape.Required("candidateChangeSet", jsonshape.Array(candidateStructure(true), 0)),
		jsonshape.Required("changedSourcePlanes", jsonshape.Nullable(texts)),
		jsonshape.Required("sourceComparisonState", jsonshape.Enum(map[string]struct{}{"compared": {}, "skipped_source_admission": {}})),
		jsonshape.Required("wholeCandidateOwnerReviewRequired", jsonshape.BooleanLiteral(true)),
		jsonshape.Required("nonAuthoritativeAdmissionPreview", jsonshape.Nullable(preview)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, len(standardNonClaims))),
		jsonshape.Required("promotionPreconditions", jsonshape.Tuple(precondition, precondition, precondition, precondition)),
		jsonshape.Required("ownerReviewPlan", jsonshape.Array(jsonshape.DiscriminatedUnion("actionKind", reviewActionStructure("review_candidate", "owner-review"), reviewActionStructure("run_admitted_validation", "post-materialization-validation"), reviewActionStructure("ask_owner", "candidate-review")), 2)),
		jsonshape.Required("ruleResults", jsonshape.Tuple(rule("candidate-source-admission", states), rule("transition-admission", stepStates), rule("non-authority", jsonshape.StringLiteral("passed")), rule("composition", stepStates))),
		jsonshape.Required("summary", jsonshape.Object(
			jsonshape.Required("authoringRefCount", count), jsonshape.Required("candidateUpdateCount", count), jsonshape.Required("failureCount", count),
			jsonshape.Required("executedWitnessCountNonClaim", jsonshape.IntegerLiteral(0)), jsonshape.Required("writtenFileCountNonClaim", jsonshape.IntegerLiteral(0)),
			jsonshape.Required("mode", jsonshape.Enum(modeSet)), jsonshape.Required("sourceAdmissionState", states), jsonshape.Required("transitionAdmissionState", stepStates),
			jsonshape.Required("targetRequirementSourceId", text), jsonshape.Required("targetRequirementsPath", text), jsonshape.Required("targetSpecPackagePath", text),
		)),
	)
	return input, output
}

func authoringReferenceShape(output bool) jsonshape.Shape {
	text := jsonshape.String()
	fields := []jsonshape.Property{jsonshape.Required("refId", text), jsonshape.Required("kind", jsonshape.Enum(refKindSet)), jsonshape.Required("path", text), jsonshape.Required("summary", text), jsonshape.Required("nonClaims", jsonshape.Array(text, 1))}
	if output {
		fields = append(fields, jsonshape.Required("digest", jsonshape.Nullable(text)))
	} else {
		fields = append(fields, jsonshape.Optional("digest", jsonshape.Nullable(text)))
	}
	return jsonshape.Object(fields...)
}

func proofObligationStructure() jsonshape.Shape {
	text := jsonshape.String()
	return jsonshape.Object(jsonshape.Required("obligationId", text), jsonshape.Required("kind", jsonshape.Enum(obligationKindSet)), jsonshape.Required("ownerId", text), jsonshape.Required("description", text), jsonshape.Required("blocking", jsonshape.Boolean()), jsonshape.Required("evidenceRefs", jsonshape.Array(text, 0)))
}

func candidateStructure(output bool) jsonshape.Shape {
	text := jsonshape.String()
	fields := []jsonshape.Property{
		jsonshape.Required("candidateId", text), jsonshape.Required("requirementId", text), jsonshape.Required("operation", jsonshape.Enum(operationSet)),
		jsonshape.Required("sourceRefIds", jsonshape.Array(text, 1)), jsonshape.Required("rationale", text), jsonshape.Required("ownerQuestions", jsonshape.Array(text, 1)),
		jsonshape.Required("declaredProofObligations", jsonshape.Array(proofObligationStructure(), 1)),
	}
	if !output {
		return jsonshape.Object(fields...)
	}
	fields = append(fields, jsonshape.Optional("candidateRequirement", requirementsourceadmission.RequirementShape()), jsonshape.Optional("candidateRequirementOmitted", jsonshape.StringLiteral(omittedCandidateMessage)))
	return jsonshape.ExactlyOne(jsonshape.Object(fields...), "candidateRequirement", "candidateRequirementOmitted")
}

func reviewActionStructure(kind, phase string) jsonshape.Shape {
	text := jsonshape.String()
	fields := []jsonshape.Property{jsonshape.Required("actionId", text), jsonshape.Required("actionKind", jsonshape.StringLiteral(kind)), jsonshape.Required("owner", jsonshape.StringLiteral("consuming_repository_owner")), jsonshape.Required("phase", jsonshape.StringLiteral(phase)), jsonshape.Required("nonClaims", jsonshape.Array(text, 1))}
	if kind == "ask_owner" {
		fields = append(fields, jsonshape.Required("candidateId", text), jsonshape.Required("requirementId", text), jsonshape.Required("declaredProofObligations", jsonshape.Array(proofObligationStructure(), 1)), jsonshape.Required("evidenceRefs", jsonshape.Array(text, 1)), jsonshape.Required("ownerQuestions", jsonshape.Array(text, 1)))
	} else {
		fields = append(fields, jsonshape.Required("instruction", text))
	}
	return jsonshape.Object(fields...)
}
