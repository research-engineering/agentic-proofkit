package requirementcontext

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const projectRootNodeID = "project.root"

type projectOrigin struct {
	manifest  adoptionmaterialization.Manifest
	inventory testevidenceinventory.Inventory
}

func (origin projectOrigin) value() map[string]any {
	return map[string]any{
		"manifest":              origin.manifest.JSONValue(),
		"testEvidenceInventory": testevidenceinventory.InventoryValue(origin.inventory),
	}
}

// FromProject derives routing context from one admitted logical project. The
// observed manifest digest records captured bytes, not ongoing file freshness.
func FromProject(project *adoptionmaterialization.Project, manifestContentDigest string) (Snapshot, error) {
	if _, err := admitDigestRef(manifestContentDigest, "project context manifest currentDigest"); err != nil {
		return Snapshot{}, err
	}
	value, err := project.JSONValue()
	if err != nil {
		return Snapshot{}, err
	}
	manifest, err := adoptionmaterialization.AdmitManifest(value["manifest"])
	if err != nil {
		return Snapshot{}, err
	}
	inventory, err := testevidenceinventory.EvaluateDirect(value["testEvidenceInventory"])
	if err != nil || inventory.ExitCode != 0 {
		return Snapshot{}, fmt.Errorf("project context test inventory is invalid")
	}
	refs := make([]requirementspectree.SourceRef, 0, len(value["requirementSources"].([]any)))
	for _, raw := range value["requirementSources"].([]any) {
		id := raw.(map[string]any)["sourceId"].(string)
		refs = append(refs, requirementspectree.SourceRef{SourceRefID: id, SourceRefKind: "source_id", SourceRole: "requirements", SourceID: id})
	}
	sort.Slice(refs, func(left, right int) bool { return refs[left].SourceRefID < refs[right].SourceRefID })
	collection := requirementspectree.Tree{
		TreeID: "project.collection", RootNodeID: projectRootNodeID,
		CallerAnnotations: []string{"This collection is routing-only and does not infer product hierarchy."},
		Nodes:             []requirementspectree.Node{{NodeID: projectRootNodeID, NodeKind: "meta_spec", Label: manifest.ProjectID, DisplayOrder: 1, SourceRefs: refs}},
	}
	projections := map[string]any{
		"requirementSources": value["requirementSources"], "proofBinding": value["proofBinding"],
		"specTree": requirementspectree.TreeValue(collection),
	}
	tree, requirements, binding, _, canonical, err := admitSnapshotProjections(projections)
	if err != nil {
		return Snapshot{}, err
	}
	origin := &projectOrigin{manifest: manifest, inventory: inventory.Inventory}
	snapshot := Snapshot{
		CatalogID: manifest.ProjectID, ExpectedDigestCoverage: "partial", ProofBinding: binding,
		Projections: canonical, RequirementSources: requirements, Tree: tree, projectOrigin: origin,
		Sources: projectSources(manifest, inventory.Inventory.InventoryID, binding.BindingID, requirements, manifestContentDigest),
	}
	snapshot.SnapshotID, err = digest.StableJSONSHA256Ref(projectSnapshotIdentity(snapshot))
	if err != nil {
		return Snapshot{}, err
	}
	return validateSnapshotSize(snapshot)
}

func projectSources(manifest adoptionmaterialization.Manifest, inventoryID, bindingID string, requirements []requirementsourceadmission.Source, manifestDigest string) []Source {
	requirementIDs := make(map[string]string, len(requirements))
	for _, source := range requirements {
		requirementIDs[source.RequirementsPath] = source.SourceID
	}
	sources := []Source{{Kind: "project_manifest", SourceRef: manifest.ProjectID, Path: adoptionmaterialization.ProjectManifestPath, CurrentDigest: manifestDigest}}
	for _, route := range manifest.Routes {
		source := Source{Path: route.Path, CurrentDigest: route.ArtifactID, ExpectedDigest: route.ArtifactID}
		switch route.ArtifactKind {
		case adoptionmaterialization.ArtifactRequirementSource:
			source.Kind, source.SourceRef = "requirement_source", requirementIDs[route.Path]
			source.NodeID, source.SourceRole = projectRootNodeID, "requirements"
		case adoptionmaterialization.ArtifactRequirementBinding:
			source.Kind, source.SourceRef = "proof_binding", bindingID
		case adoptionmaterialization.ArtifactTestInventory:
			source.Kind, source.SourceRef = "test_inventory", inventoryID
		}
		sources = append(sources, source)
	}
	sortSourceInventory(sources, true)
	return sources
}

func projectSnapshotIdentity(snapshot Snapshot) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("3"), "catalogId": snapshot.CatalogID,
		"projectOrigin": snapshot.projectOrigin.value(), "projections": snapshot.Projections,
		"sources": sourceIdentityValues(snapshot.Sources),
	}
}

func admitProjectSnapshot(record map[string]any) (Snapshot, error) {
	if err := admit.KnownKeys(record, []string{"catalogId", "contextKind", "expectedDigestCoverage", "nonClaims", "projectOrigin", "projections", "schemaVersion", "snapshotId", "sources"}, "project context"); err != nil {
		return Snapshot{}, err
	}
	if record["contextKind"] != ContextKind || record["expectedDigestCoverage"] != "partial" {
		return Snapshot{}, fmt.Errorf("project context identity or expectedDigestCoverage is invalid")
	}
	catalogID, err := admit.RuleID(record["catalogId"], "project context catalogId")
	if err != nil {
		return Snapshot{}, err
	}
	encoded, err := stablejson.Marshal(record)
	if err != nil || len(encoded) > maxSnapshotBytes {
		return Snapshot{}, fmt.Errorf("project context exceeds the JSON byte boundary")
	}
	if err := admitExactNonClaims(record["nonClaims"], boundaryNonClaims); err != nil {
		return Snapshot{}, err
	}
	origin, ok := record["projectOrigin"].(map[string]any)
	if !ok {
		return Snapshot{}, fmt.Errorf("project context origin must be an object")
	}
	if err := admit.KnownKeys(origin, []string{"manifest", "testEvidenceInventory"}, "project context origin"); err != nil {
		return Snapshot{}, err
	}
	projections, ok := record["projections"].(map[string]any)
	if !ok {
		return Snapshot{}, fmt.Errorf("project context projections must be an object")
	}
	if err := admit.KnownKeys(projections, []string{"proofBinding", "requirementSources", "specTree"}, "project context projections"); err != nil {
		return Snapshot{}, err
	}
	project, err := adoptionmaterialization.AdmitProject(map[string]any{
		"manifest": origin["manifest"], "testEvidenceInventory": origin["testEvidenceInventory"],
		"proofBinding": projections["proofBinding"], "requirementSources": projections["requirementSources"],
	})
	if err != nil {
		return Snapshot{}, err
	}
	sources, err := admitSourceInventory(record["sources"], true)
	if err != nil {
		return Snapshot{}, err
	}
	manifestDigest := ""
	for _, source := range sources {
		if source.Kind == "project_manifest" {
			if manifestDigest != "" {
				return Snapshot{}, fmt.Errorf("project context requires one physical manifest")
			}
			manifestDigest = source.CurrentDigest
		}
	}
	expected, err := FromProject(project, manifestDigest)
	if err != nil {
		return Snapshot{}, err
	}
	tree, err := requirementspectree.Evaluate(projections["specTree"])
	if err != nil || tree.ExitCode != 0 {
		return Snapshot{}, fmt.Errorf("project context spec tree is invalid")
	}
	// Identity and derivation are independent obligations: a caller can rehash
	// a valid but unrelated tree, so integrity cannot replace owner replay.
	actual := expected
	actual.CatalogID = catalogID
	actual.Sources = sources
	actual.Projections = map[string]any{
		"specTree":           requirementspectree.TreeValue(tree.Tree),
		"proofBinding":       expected.Projections["proofBinding"],
		"requirementSources": expected.Projections["requirementSources"],
	}
	id, err := digest.StableJSONSHA256Ref(projectSnapshotIdentity(actual))
	if err != nil || record["snapshotId"] != id {
		return Snapshot{}, fmt.Errorf("project context identity does not match admitted content")
	}
	if !reflect.DeepEqual(actual.Projections["specTree"], expected.Projections["specTree"]) {
		return Snapshot{}, fmt.Errorf("project context spec tree must equal the derived collection")
	}
	if !reflect.DeepEqual(sources, expected.Sources) {
		return Snapshot{}, fmt.Errorf("project context physical sources must equal the manifest route partition")
	}
	if catalogID != expected.CatalogID {
		return Snapshot{}, fmt.Errorf("project context catalogId must equal the project identity")
	}
	return expected, nil
}
