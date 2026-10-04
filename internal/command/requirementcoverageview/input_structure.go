package requirementcoverageview

import (
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func InputStructure() (map[string]any, error) {
	source, err := requirementsourcecodec.InputStructure(requirementsourcemodel.DefaultLimits())
	if err != nil {
		return nil, err
	}
	schema := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(3)),
		jsonshape.Required("viewInputId", jsonshape.String()),
		jsonshape.Required("coverageUniverse", CoverageUniverseShape()),
		jsonshape.Optional("options", jsonshape.Nullable(OptionsShape())),
		jsonshape.Optional("ownerInvariantRegistry", jsonshape.Nullable(OwnerInvariantRegistryShape())),
		jsonshape.Optional("localEnvironmentPolicy", jsonshape.Nullable(LocalEnvironmentPolicyShape())),
	).JSONSchema()
	schema["$id"] = "urn:proofkit:requirement-coverage-view:input:schema:3"
	schema["$defs"] = map[string]any{
		"compactProofContract": compactproofcontract.InputStructure(),
		"normalizedInventory":  testevidenceinventory.NormalizedInputStructure(),
	}
	properties := schema["properties"].(map[string]any)
	properties["requirementSource"] = source
	properties["requirementProofBinding"] = nullableStructure(requirementbinding.InputStructure())
	properties["compactProofContract"] = nullableStructure(map[string]any{"$ref": "#/$defs/compactProofContract"})
	properties["testEvidenceInventory"] = nullableStructure(testevidenceinventory.InventoryInputShape().JSONSchema())
	properties["normalizedTestEvidenceInventory"] = nullableStructure(map[string]any{"$ref": "#/$defs/normalizedInventory"})
	required := append(schema["required"].([]any), "requirementSource")
	slices.SortFunc(required, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
	schema["required"] = required
	schema["oneOf"] = []any{
		map[string]any{"required": []any{"requirementProofBinding"}, "properties": map[string]any{
			"requirementProofBinding": map[string]any{"type": "object"}, "compactProofContract": map[string]any{"type": "null"},
		}},
		map[string]any{"required": []any{"compactProofContract", "localEnvironmentPolicy"}, "properties": map[string]any{
			"compactProofContract": map[string]any{"type": "object"}, "requirementProofBinding": map[string]any{"type": "null"},
			"localEnvironmentPolicy": map[string]any{"type": "object"},
		}},
	}
	schema["description"] = "Exactly one non-null proof binding is required; compact mode also requires non-null localEnvironmentPolicy. Native owners retain source/scenario links, inventory classification, provenance joins, canonical text/path rules and coverage semantics. Structural validity does not prove coverage or execution."
	return schema, nil
}

func nullableStructure(schema map[string]any) map[string]any {
	return map[string]any{"anyOf": []any{map[string]any{"type": "null"}, schema}}
}

func CoverageUniverseShape() jsonshape.Shape {
	text := jsonshape.String()
	surfaces := jsonshape.Array(jsonshape.Object(
		jsonshape.Required("surfaceId", text), jsonshape.Required("ownerId", text), jsonshape.Required("path", text),
	), 0)
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("authority", jsonshape.StringLiteral("caller_owned_inventory")),
		jsonshape.Required("universeId", text),
		jsonshape.Required("completenessDeclaration", jsonshape.Enum(map[string]struct{}{
			"full_repository": {}, "selected_owner_surfaces": {}, "selected_paths_advisory": {},
		})),
		jsonshape.Required("ownerIds", jsonshape.Array(text, 1)),
		jsonshape.Required("commandRefs", jsonshape.Array(text, 0)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Required("codeSurfaces", surfaces), jsonshape.Required("specSurfaces", surfaces), jsonshape.Required("testSurfaces", surfaces),
	)
}

func OwnerInvariantRegistryShape() jsonshape.Shape {
	text := jsonshape.String()
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("registryId", text), jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Required("invariants", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("ownerInvariantId", text), jsonshape.Required("ownerId", text),
			jsonshape.Required("sourcePath", text), jsonshape.Required("summary", text),
			jsonshape.Required("nonClaims", jsonshape.Array(text, 0)),
		), 0)),
	)
}

func LocalEnvironmentPolicyShape() jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("authority", jsonshape.StringLiteral("caller_provided")),
		jsonshape.Required("localEnvironmentClasses", jsonshape.Array(jsonshape.String(), 0)),
	)
}

func OptionsShape() jsonshape.Shape {
	return jsonshape.Object(jsonshape.Optional("scope", jsonshape.String()))
}
