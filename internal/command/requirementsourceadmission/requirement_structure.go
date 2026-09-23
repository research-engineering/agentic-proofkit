package requirementsourceadmission

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

var requirementShape = atomicRequirementStructure()

// RequirementShape owns RequirementValue's effective, non-editable projection.
// Deferral is absent when unavailable; complete-source fields remain elsewhere.
func RequirementShape() jsonshape.Shape { return requirementShape }

// LifecycleStateShape shares the source admission vocabulary with context queries.
func LifecycleStateShape() jsonshape.Shape { return jsonshape.Enum(lifecycleStateSet) }

// NonClaimDefinitionsShape describes the resolved dictionary shared by views.
func NonClaimDefinitionsShape() jsonshape.Shape {
	source, err := requirementsourcecodec.InputShape(requirementsourcemodel.DefaultLimits())
	if err != nil {
		panic("invalid source structure for non-claim dictionary")
	}
	return structureProperty(source, "nonClaimDefinitions")
}

// ComparisonValueShape describes effective owner fields, not arbitrary JSON.
func ComparisonValueShape() jsonshape.Shape {
	return jsonshape.OneOf(
		jsonshape.Null(), jsonshape.String(), jsonshape.Array(jsonshape.String(), 0), requirementShape,
		structureProperty(requirementShape, "lifecycle"), structureProperty(requirementShape, "updatePolicy"),
		structureProperty(requirementShape, "deferral"),
	)
}

func atomicRequirementStructure() jsonshape.Shape {
	source, err := requirementsourcecodec.InputShape(requirementsourcemodel.DefaultLimits())
	if err != nil {
		panic("invalid source structure for requirement projection")
	}
	group := structureElement(structureProperty(source, "groups"))
	member := structureElement(structureProperty(group, "members"))
	metadata := structureProperty(member, "fields")
	lifecycle, policy := structureProperty(metadata, "lifecycle"), structureProperty(metadata, "updatePolicy")
	fields := []jsonshape.Property{
		jsonshape.Required("requirementId", structureProperty(member, "requirementId")),
		jsonshape.Required("invariant", jsonshape.String()),
		jsonshape.Required("sharedPremises", structureProperty(group, "sharedPremises")),
		jsonshape.Required("lifecycle", jsonshape.Object(
			jsonshape.Required("state", structureProperty(lifecycle, "state")),
			jsonshape.Required("evidenceRefs", structureProperty(lifecycle, "evidenceRefs")),
			jsonshape.Required("replacementRequirementIds", structureProperty(lifecycle, "replacementRequirementIds")),
		)),
		jsonshape.Required("updatePolicy", jsonshape.Object(
			jsonshape.Required("reviewOwnerId", structureProperty(policy, "reviewOwnerId")),
			jsonshape.Required("requiresImpactDeclaration", structureProperty(policy, "requiresImpactDeclaration")),
			jsonshape.Required("requiresProofBindingReview", structureProperty(policy, "requiresProofBindingReview")),
		)),
		jsonshape.Optional("deferral", jsonshape.NonNullable(structureProperty(metadata, "deferral"))),
	}
	for _, key := range []string{"claimLevel", "externalNonClaimRefs", "nonClaimRefs", "nonClaims", "ownerId", "proofBindingRefs", "riskClass"} {
		fields = append(fields, jsonshape.Required(key, structureProperty(metadata, key)))
	}
	return jsonshape.Object(fields...)
}

func structureProperty(shape jsonshape.Shape, name string) jsonshape.Shape {
	child, ok := shape.Property(name)
	if !ok {
		panic("requirement projection references an absent structural property")
	}
	return child
}

func structureElement(shape jsonshape.Shape) jsonshape.Shape {
	child, ok := shape.Element()
	if !ok {
		panic("requirement projection references a non-array structure")
	}
	return child
}
