package requirementcoverageview

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

var coverageOutputShape = jsonshape.DiscriminatedUnion("proofMode", coverageOutputVariant("compact"), coverageOutputVariant("structured"))

// OutputShape describes complete coverage output, not a lookup fragment.
// Native re-admission additionally replays identities, relations and diagnostics.
func OutputShape() jsonshape.Shape    { return coverageOutputShape }
func OutputStructure() map[string]any { return coverageOutputShape.JSONSchema() }

func coverageOutputVariant(mode string) jsonshape.Shape {
	text, count := jsonshape.String(), jsonshape.IntegerMinimum(0)
	texts := jsonshape.Array(text, 0)
	state := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	basis := jsonshape.Object(
		jsonshape.Required("ownerIds", jsonshape.Array(text, 1)),
		jsonshape.Required("testInventoryDigest", jsonshape.Nullable(text)),
		jsonshape.Required("fullRepositoryOutOfScopeSourceRequirements", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("ownerId", text), jsonshape.Required("requirementId", text),
		), 0)),
	)
	fields := []jsonshape.Property{
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(4)),
		jsonshape.Required("viewKind", jsonshape.StringLiteral("proofkit.requirement-coverage-view")),
		jsonshape.Required("authority", jsonshape.StringLiteral("lookup_only")),
		jsonshape.Required("proofMode", jsonshape.StringLiteral(mode)),
		jsonshape.Required("state", state),
		jsonshape.Required("testInventoryId", jsonshape.Nullable(text)),
		jsonshape.Required("completenessDeclaration", jsonshape.Enum(map[string]struct{}{
			"full_repository": {}, "selected_owner_surfaces": {}, "selected_paths_advisory": {},
		})),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Required("sourceDigest", jsonshape.String()),
		jsonshape.Required("nonClaimDefinitions", requirementsourceadmission.NonClaimDefinitionsShape()),
		jsonshape.Required("coverageBasis", basis),
		jsonshape.Required("requirementCoverage", jsonshape.Array(coverageRequirementShape(mode), 0)),
		jsonshape.Required("ownerInvariantCoverage", jsonshape.Array(coverageOwnerInvariantShape(), 0)),
		jsonshape.Required("commandCoverage", jsonshape.Array(coverageCommandShape(), 0)),
		jsonshape.Required("unmappedTests", jsonshape.Array(coverageTestShape(), 0)),
		jsonshape.Required("deadZones", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("deadZoneKind", jsonshape.Enum(map[string]struct{}{
				"unbound_code_surface": {}, "unbound_spec_surface": {}, "unbound_test_surface": {},
			})),
			jsonshape.Required("ownerId", text), jsonshape.Required("path", text), jsonshape.Required("surfaceId", text),
		), 0)),
		jsonshape.Required("failures", texts), jsonshape.Required("warnings", texts),
		jsonshape.Required("failureClassifications", coverageClassificationsShape("failure")),
		jsonshape.Required("warningClassifications", coverageClassificationsShape("warning")),
		jsonshape.Required("guidanceSummary", jsonshape.Object(
			jsonshape.Required("failureCount", count), jsonshape.Required("warningCount", count),
			jsonshape.Required("state", state), jsonshape.Required("nextAction", text), jsonshape.Required("nonClaim", text),
		)),
	}
	for _, name := range []string{"viewInputId", "coverageUniverseId", "sourceId", "ownerInvariantRegistryId", "bindingId", "contractId"} {
		field := text
		if (mode == "compact" && name == "bindingId") || (mode == "structured" && name == "contractId") {
			field = jsonshape.StringLiteral("")
		}
		fields = append(fields, jsonshape.Required(name, field))
	}
	for _, name := range []string{"commandCoverageCount", "ownerInvariantCoverageCount", "requirementCoverageCount", "failureCount", "warningCount"} {
		fields = append(fields, jsonshape.Required(name, count))
	}
	return jsonshape.Object(fields...)
}

func coverageClassificationsShape(severity string) jsonshape.Shape {
	return jsonshape.Array(jsonshape.Object(
		jsonshape.Required("classificationId", jsonshape.String()),
		jsonshape.Required("diagnostic", jsonshape.String()),
		jsonshape.Required("severity", jsonshape.StringLiteral(severity)),
	), 0)
}
