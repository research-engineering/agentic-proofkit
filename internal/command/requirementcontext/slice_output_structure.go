package requirementcontext

import (
	"maps"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

var sliceOutputShape = makeSliceOutputShape()

func makeSliceOutputShape() jsonshape.Shape {
	variants := make([]jsonshape.Shape, 0, len(sliceProfiles))
	for _, profile := range slices.Sorted(maps.Keys(sliceProfiles)) {
		variants = append(variants, sliceOutputVariant(profile))
	}
	return jsonshape.DiscriminatedUnion("profile", variants...)
}

func SliceOutputStructure() map[string]any { return sliceOutputShape.JSONSchema() }

func sliceOutputVariant(profile string) jsonshape.Shape {
	text, count := jsonshape.String(), jsonshape.IntegerMinimum(0)
	fragment := jsonshape.Object(
		jsonshape.Required("authority", jsonshape.StringLiteral("lookup_fragment_only")),
		jsonshape.Required("projectionKind", jsonshape.StringLiteral("proofkit.requirement-source-fragment")),
		jsonshape.Required("sourceId", text),
		jsonshape.Required("requirements", jsonshape.Array(requirementsourceadmission.RequirementShape(), 1)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 0)),
		jsonshape.Required("nonClaimDefinitions", requirementsourceadmission.NonClaimDefinitionsShape()),
		jsonshape.Required("omittedRequirementCount", count), jsonshape.Required("selectedRequirementCount", count), jsonshape.Required("totalRequirementCount", count),
	)
	projections := []jsonshape.Property{
		jsonshape.Required("requirementSources", jsonshape.Array(fragment, 0)),
		jsonshape.Required("specTree", requirementspectree.FragmentShape()),
	}
	if profile == "proof" || profile == "review" {
		projections = append(projections, jsonshape.Optional("proofBinding", requirementbinding.SelectionFragmentShape()))
	}
	if profile == "coverage" || profile == "review" {
		projections = append(projections, jsonshape.Optional("coverage", requirementcoverageview.FragmentShape()))
	}
	denials := make([]jsonshape.Shape, len(boundaryNonClaims))
	for i, value := range boundaryNonClaims {
		denials[i] = jsonshape.StringLiteral(value)
	}
	omission := func(kind, reason string) jsonshape.Shape {
		return jsonshape.Object(
			jsonshape.Required("kind", jsonshape.StringLiteral(kind)), jsonshape.Required("reason", jsonshape.StringLiteral(reason)),
			jsonshape.Required("count", jsonshape.IntegerMinimum(1)),
		)
	}
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)),
		jsonshape.Required("contextKind", jsonshape.StringLiteral("proofkit.requirement-context-slice")),
		jsonshape.Required("sliceId", text), jsonshape.Required("snapshotId", text),
		jsonshape.Required("profile", jsonshape.StringLiteral(profile)),
		jsonshape.Required("state", jsonshape.Enum(map[string]struct{}{"selected": {}, "no_match": {}})),
		jsonshape.Required("nonClaims", jsonshape.Tuple(denials...)),
		jsonshape.Required("projections", jsonshape.Object(projections...)),
		jsonshape.Required("omissions", jsonshape.Array(jsonshape.OneOf(omission("nodes", "max_depth"), omission("nodes", "max_nodes"), omission("requirements", "max_requirements")), 0)),
	)
}
