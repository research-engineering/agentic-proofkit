package requirementsourceview

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

const (
	viewSchemaVersion = 2
	viewKind          = "proofkit.requirement-source-view"
)

var sourceViewShape = sourceViewStructure()

func OutputStructure() map[string]any { return sourceViewShape.JSONSchema() }

func sourceViewStructure() jsonshape.Shape {
	limits := requirementsourcemodel.DefaultLimits()
	source, err := requirementsourcecodec.InputShape(limits)
	if err != nil {
		panic("invalid source structure for view declaration")
	}
	group := shapeElement(shapeProperty(source, "groups"))
	member := shapeElement(shapeProperty(group, "members"))
	atomic := requirementsourceadmission.RequirementShape()
	lifecycle := shapeProperty(atomic, "lifecycle")
	text, count := jsonshape.String(), jsonshape.IntegerMinimum(0)
	fields := []jsonshape.Property{
		jsonshape.Required("requirementId", shapeProperty(member, "requirementId")),
		jsonshape.Required("invariant", text),
		jsonshape.Required("sharedPremises", shapeProperty(group, "sharedPremises")),
		jsonshape.Required("lifecycleState", shapeProperty(lifecycle, "state")),
		jsonshape.Required("lifecycleEvidenceRefs", shapeProperty(lifecycle, "evidenceRefs")),
		jsonshape.Required("replacementRequirementIds", shapeProperty(lifecycle, "replacementRequirementIds")),
		jsonshape.Required("updatePolicy", shapeProperty(atomic, "updatePolicy")),
		jsonshape.Required("deferral", jsonshape.Nullable(shapeProperty(atomic, "deferral"))),
	}
	for _, key := range []string{"claimLevel", "externalNonClaimRefs", "nonClaimRefs", "nonClaims", "ownerId", "proofBindingRefs", "riskClass", "sourceReviewDigest"} {
		fields = append(fields, jsonshape.Required(key, shapeProperty(atomic, key)))
	}
	properties := []jsonshape.Property{
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(viewSchemaVersion)),
		jsonshape.Required("viewKind", jsonshape.StringLiteral(viewKind)),
		jsonshape.Required("authority", jsonshape.StringLiteral("presentation_only")),
		jsonshape.Required("activeRequirementCount", count),
		jsonshape.Required("blockingRequirementCount", count),
		jsonshape.Required("deferredRequirementCount", count),
		jsonshape.Required("requirementCount", count),
		jsonshape.Required("nonClaims", jsonshape.BoundedArray(text, len(defaultNonClaims), limits.MaxCollectionItems+limits.MaxDefinitions+len(defaultNonClaims))),
		jsonshape.Required("requirements", jsonshape.BoundedArray(jsonshape.Object(fields...), 0, limits.MaxMembers)),
		jsonshape.Required("groups", jsonshape.BoundedArray(jsonshape.Object(
			jsonshape.Required("groupId", shapeProperty(group, "groupId")),
			jsonshape.Required("statementStem", shapeProperty(group, "statementStem")),
			jsonshape.Required("sharedPremises", shapeProperty(group, "sharedPremises")),
			jsonshape.Required("requirementIds", jsonshape.BoundedArray(shapeProperty(member, "requirementId"), 1, limits.MaxMembersPerGroup)),
		), 0, limits.MaxGroups)),
		jsonshape.Required("overviewPath", text),
		jsonshape.Required("requirementsPath", jsonshape.StringSuffix(requirementsourceadmission.RequirementsFileSuffix)),
	}
	for _, key := range []string{"sourceId", "specPackagePath", "sourceNonClaimRefs", "nonClaimDefinitions", "vocabulary", "scenarios", "derivations"} {
		properties = append(properties, jsonshape.Required(key, shapeProperty(source, key)))
	}
	return jsonshape.Object(properties...)
}

func shapeProperty(shape jsonshape.Shape, name string) jsonshape.Shape {
	child, ok := shape.Property(name)
	if !ok {
		panic("source view references an absent structural property")
	}
	return child
}

func shapeElement(shape jsonshape.Shape) jsonshape.Shape {
	child, ok := shape.Element()
	if !ok {
		panic("source view references a non-array structural property")
	}
	return child
}
