package requirementsourceconversion

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

const (
	FlatDocumentKind  = "proofkit.requirement-source-flat"
	FlatSchemaVersion = 1
)

// flatFieldIDs is the complete resolved metadata inventory of one flat
// requirement record. The grouped metadata shape owns each value grammar, and
// the model owns the exclusive profile/member partition over these names.
var flatFieldIDs = []string{
	"claimLevel", "deferral", "externalNonClaimRefs", "lifecycle", "nonClaimRefs",
	"nonClaims", "ownerId", "proofBindingRefs", "riskClass", "updatePolicy",
}

var (
	groupedShape = newGroupedShape()
	flatShape    = newFlatShape(groupedShape, requirementsourcemodel.DefaultLimits())
)

// GroupedStructure is the grouped source structure read by --to flat and
// emitted by --to grouped. It is the grouped codec's own descriptor.
func GroupedStructure() map[string]any { return groupedShape.JSONSchema() }

// FlatStructure is the flat document structure emitted by --to flat and read
// by --to grouped.
func FlatStructure() map[string]any { return flatShape.JSONSchema() }

func newGroupedShape() jsonshape.Shape {
	shape, err := requirementsourcecodec.InputShape(requirementsourcemodel.DefaultLimits())
	if err != nil {
		panic("requirement source conversion has no grouped source structure")
	}
	return shape
}

// newFlatShape reuses the grouped descriptor for every shared value grammar.
// Only the record layout and reconstruction coordinates are flat-specific.
func newFlatShape(grouped jsonshape.Shape, limits requirementsourcemodel.Limits) jsonshape.Shape {
	group := element(property(grouped, "groups"))
	member := element(property(group, "members"))
	metadata := property(member, "fields")
	fields := make([]jsonshape.Property, len(flatFieldIDs))
	fieldNames := make(map[string]struct{}, len(flatFieldIDs))
	for index, name := range flatFieldIDs {
		fields[index] = jsonshape.Required(name, property(metadata, name))
		fieldNames[name] = struct{}{}
	}
	requirement := jsonshape.Object(
		jsonshape.Required("requirementId", property(member, "requirementId")),
		jsonshape.Required("invariant", property(member, "statementCompletion")),
		jsonshape.Required("sharedPremises", property(group, "sharedPremises")),
		jsonshape.Required("fields", jsonshape.Object(fields...)),
	)
	profile := jsonshape.Object(
		jsonshape.Required("profileId", property(element(property(grouped, "profiles")), "profileId")),
		jsonshape.Required("fieldIds", jsonshape.BoundedArray(jsonshape.Enum(fieldNames), 0, len(flatFieldIDs))),
	)
	coordinates := jsonshape.Object(
		jsonshape.Required("groupId", property(group, "groupId")),
		jsonshape.Required("profileId", property(group, "profileId")),
		jsonshape.Required("statementStemBytes", jsonshape.IntegerRange(0, int64(limits.MaxTotalTextBytes))),
		jsonshape.Required("requirementIds", jsonshape.BoundedArray(property(member, "requirementId"), 0, limits.MaxMembersPerGroup)),
	)
	return jsonshape.Object(
		jsonshape.Required("kind", jsonshape.StringLiteral(FlatDocumentKind)),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(FlatSchemaVersion)),
		jsonshape.Required("basisDigest", jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)),
		jsonshape.Required("sourceId", property(grouped, "sourceId")),
		jsonshape.Required("specPackagePath", property(grouped, "specPackagePath")),
		jsonshape.Required("sourceNonClaims", property(grouped, "sourceNonClaims")),
		jsonshape.Required("sourceNonClaimRefs", property(grouped, "sourceNonClaimRefs")),
		jsonshape.Required("nonClaimDefinitions", property(grouped, "nonClaimDefinitions")),
		jsonshape.Required("vocabulary", property(grouped, "vocabulary")),
		jsonshape.Required("derivations", property(grouped, "derivations")),
		jsonshape.Required("scenarios", property(grouped, "scenarios")),
		jsonshape.Required("profiles", jsonshape.BoundedArray(profile, 0, limits.MaxProfiles)),
		jsonshape.Required("groups", jsonshape.BoundedArray(coordinates, 0, limits.MaxGroups)),
		jsonshape.Required("requirements", jsonshape.BoundedArray(requirement, 0, limits.MaxMembers)),
	)
}

func property(shape jsonshape.Shape, name string) jsonshape.Shape {
	child, ok := shape.Property(name)
	if !ok {
		panic("requirement source conversion references an absent structural property: " + name)
	}
	return child
}

func element(shape jsonshape.Shape) jsonshape.Shape {
	child, ok := shape.Element()
	if !ok {
		panic("requirement source conversion references a non-array structural property")
	}
	return child
}
