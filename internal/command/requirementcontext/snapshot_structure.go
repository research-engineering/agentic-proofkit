package requirementcontext

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

var catalogSnapshotShape = makeSnapshotShape(false)
var projectSnapshotShape = makeSnapshotShape(true)

// SnapshotShape describes both admitted origins; compose emits only catalogs.
func SnapshotShape() jsonshape.Shape {
	return jsonshape.OneOf(catalogSnapshotShape, projectSnapshotShape)
}
func CatalogSnapshotStructure() map[string]any { return catalogSnapshotShape.JSONSchema() }

func makeSnapshotShape(project bool) jsonshape.Shape {
	text := jsonshape.String()
	source, err := requirementsourcecodec.InputShape(requirementsourcemodel.DefaultLimits())
	if err != nil {
		panic("invalid requirement source structure")
	}
	projection := []jsonshape.Property{
		jsonshape.Required("specTree", requirementspectree.InputShape()),
		jsonshape.Required("requirementSources", jsonshape.Array(source, 1)),
	}
	digestCoverage := jsonshape.Enum(map[string]struct{}{"all": {}, "none": {}, "partial": {}})
	if project {
		projection = append(projection, jsonshape.Required("proofBinding", requirementbinding.InputShape()))
		digestCoverage = jsonshape.StringLiteral("partial")
	} else {
		projection = append(projection, jsonshape.Optional("proofBinding", requirementbinding.InputShape()),
			jsonshape.Optional("coverage", requirementcoverageview.OutputShape()))
	}
	nonClaims := make([]jsonshape.Shape, len(boundaryNonClaims))
	for i, value := range boundaryNonClaims {
		nonClaims[i] = jsonshape.StringLiteral(value)
	}
	fields := []jsonshape.Property{
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(SnapshotSchemaVersion)),
		jsonshape.Required("contextKind", jsonshape.StringLiteral(ContextKind)),
		jsonshape.Required("catalogId", text), jsonshape.Required("snapshotId", text),
		jsonshape.Required("expectedDigestCoverage", digestCoverage),
		jsonshape.Required("nonClaims", jsonshape.Tuple(nonClaims...)),
		jsonshape.Required("projections", jsonshape.Object(projection...)),
		jsonshape.Required("sources", jsonshape.Array(snapshotSourceShape(project), 1)),
	}
	if project {
		fields = append(fields, jsonshape.Required("projectOrigin", jsonshape.Object(
			jsonshape.Required("manifest", adoptionmaterialization.ManifestShape()),
			jsonshape.Required("testEvidenceInventory", testevidenceinventory.DirectInputShape()),
		)))
	}
	return jsonshape.Object(fields...)
}

func snapshotSourceShape(project bool) jsonshape.Shape {
	kinds := []string{"coverage", "proof_binding", "requirement_source", "spec_tree"}
	if project {
		kinds = []string{"project_manifest", "test_inventory", "proof_binding", "requirement_source"}
	}
	branches := make([]jsonshape.Shape, 0, len(kinds))
	for _, kind := range kinds {
		text := jsonshape.String()
		fields := []jsonshape.Property{
			jsonshape.Required("kind", jsonshape.StringLiteral(kind)),
			jsonshape.Required("path", text), jsonshape.Required("sourceRef", text),
			jsonshape.Required("currentDigest", text), jsonshape.Optional("expectedDigest", jsonshape.Nullable(text)),
		}
		if kind == "requirement_source" {
			fields = append(fields, jsonshape.Required("nodeId", text), jsonshape.Required("sourceRole", jsonshape.StringLiteral("requirements")))
		} else {
			fields = append(fields, jsonshape.Optional("nodeId", jsonshape.Null()), jsonshape.Optional("sourceRole", jsonshape.Null()))
		}
		branches = append(branches, jsonshape.Object(fields...))
	}
	return jsonshape.DiscriminatedUnion("kind", branches...)
}
