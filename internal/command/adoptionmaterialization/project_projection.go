package adoptionmaterialization

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

// Project retains only a complete, child-admitted, cross-record-closed project.
// It does not establish repository freshness or native witness execution.
type Project struct {
	snapshot *materializedProjectSnapshot
}

// JSONValue delegates child serialization to each semantic owner and returns
// fresh nested values, so consumers cannot mutate the retained cohort.
func (project *Project) JSONValue() (map[string]any, error) {
	if project == nil || project.snapshot == nil {
		return nil, fmt.Errorf("materialized project is unavailable")
	}
	snapshot := project.snapshot
	sources := make([]any, 0, len(snapshot.Sources))
	for _, source := range snapshot.Sources {
		sources = append(sources, requirementsourceadmission.SourceValue(source))
	}
	return map[string]any{
		"manifest":              snapshot.Manifest.JSONValue(),
		"proofBinding":          requirementbinding.InputValue(snapshot.Binding),
		"requirementSources":    sources,
		"testEvidenceInventory": testevidenceinventory.InventoryValue(snapshot.Inventory),
	}, nil
}

// AdmitProject replays a logical project projection through the materialization
// owner. Route digests bind canonical child bytes, not a new filesystem read.
func AdmitProject(raw any) (*Project, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("materialized project must be an object")
	}
	if err := admit.KnownKeys(record, []string{"manifest", "proofBinding", "requirementSources", "testEvidenceInventory"}, "materialized project"); err != nil {
		return nil, err
	}
	manifest, err := AdmitManifest(record["manifest"])
	if err != nil {
		return nil, err
	}
	sources, err := admitSources(record["requirementSources"])
	if err != nil {
		return nil, err
	}
	var bindingPath, inventoryPath string
	for _, route := range manifest.Routes {
		switch route.ArtifactKind {
		case ArtifactRequirementBinding:
			bindingPath = route.Path
		case ArtifactTestInventory:
			inventoryPath = route.Path
		}
	}
	_, binding, err := admitBindingArtifact(map[string]any{"path": bindingPath, "record": record["proofBinding"]})
	if err != nil {
		return nil, err
	}
	_, inventory, err := admitInventoryArtifact(map[string]any{"path": inventoryPath, "record": record["testEvidenceInventory"]})
	if err != nil {
		return nil, err
	}
	snapshot := materializedProjectSnapshot{
		Binding: binding, BindingPath: bindingPath,
		Inventory: inventory, InventoryPath: inventoryPath,
		Manifest: manifest, Sources: sources,
	}
	if err := validateMaterializedProjectSnapshot(snapshot); err != nil {
		return nil, err
	}
	return &Project{snapshot: &snapshot}, nil
}
