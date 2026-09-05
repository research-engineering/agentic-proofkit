package adoptionmaterialization

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

// RoutedProjectRecord is one manifest-routed record observed by a read-only
// caller. Content remains untrusted until AdmitMaterializedProject returns.
type RoutedProjectRecord struct {
	Content []byte
	Path    string
}

// RoutedProjectRecordAdmission is the canonical child-owner result for one
// supplied manifest route.
type RoutedProjectRecordAdmission struct {
	Admitted      bool
	DigestMatches bool
	Path          string
}

// MaterializedProjectAdmission separates child admission from cross-record
// closure. Closure is evaluated only for a complete, digest-matched, admitted
// route set.
type MaterializedProjectAdmission struct {
	ClosureAdmitted  bool
	ClosureEvaluated bool
	Records          []RoutedProjectRecordAdmission
}

type materializedProjectSnapshot struct {
	Binding       requirementbinding.Input
	BindingPath   string
	Inventory     testevidenceinventory.Inventory
	InventoryPath string
	Manifest      Manifest
	Sources       []requirementsourceadmission.Source
}

type admittedProjectChildren struct {
	binding       requirementbinding.Input
	bindingPath   string
	inventory     testevidenceinventory.Inventory
	inventoryPath string
	sources       []requirementsourceadmission.Source
}

// AdmitMaterializedProject routes child bytes through their semantic owners and
// evaluates the adoption-materialization closure without reading a repository
// or establishing freshness or execution.
func AdmitMaterializedProject(manifest Manifest, records []RoutedProjectRecord) (MaterializedProjectAdmission, error) {
	admittedManifest, err := AdmitManifest(manifest.JSONValue())
	if err != nil || !sameManifest(manifest, admittedManifest) {
		return MaterializedProjectAdmission{}, fmt.Errorf("materialized project manifest is not admitted")
	}
	manifest = admittedManifest
	records = snapshotRoutedProjectRecords(records)
	if len(records) > len(manifest.Routes) {
		return MaterializedProjectAdmission{}, fmt.Errorf("materialized project has more records than manifest routes")
	}

	byPath := make(map[string][]byte, len(records))
	routesByPath := make(map[string]Route, len(manifest.Routes))
	for _, route := range manifest.Routes {
		routesByPath[route.Path] = route
	}
	for _, record := range records {
		if _, exists := routesByPath[record.Path]; !exists {
			return MaterializedProjectAdmission{}, fmt.Errorf("materialized project record is outside the manifest")
		}
		if _, duplicate := byPath[record.Path]; duplicate {
			return MaterializedProjectAdmission{}, fmt.Errorf("materialized project record paths must be unique")
		}
		byPath[record.Path] = record.Content
	}

	children := admittedProjectChildren{}
	result := MaterializedProjectAdmission{Records: make([]RoutedProjectRecordAdmission, 0, len(records))}
	complete := len(records) == len(manifest.Routes)
	for _, route := range manifest.Routes {
		content, present := byPath[route.Path]
		if !present {
			complete = false
			continue
		}
		item := RoutedProjectRecordAdmission{Path: route.Path}
		if len(content) <= repositorytransaction.MaximumFileBytes && digest.SHA256BytesRef(content) == route.ArtifactID {
			item.DigestMatches = true
			_, item.Admitted = admitProjectChildRecord(content, route, &children)
		}
		complete = complete && item.DigestMatches && item.Admitted
		result.Records = append(result.Records, item)
	}
	if !complete {
		return result, nil
	}

	result.ClosureEvaluated = true
	snapshot := materializedProjectSnapshot{
		Binding: children.binding, BindingPath: children.bindingPath,
		Inventory: children.inventory, InventoryPath: children.inventoryPath,
		Manifest: manifest, Sources: children.sources,
	}
	result.ClosureAdmitted = validateMaterializedProjectSnapshot(snapshot) == nil
	return result, nil
}

func snapshotRoutedProjectRecords(records []RoutedProjectRecord) []RoutedProjectRecord {
	result := make([]RoutedProjectRecord, len(records))
	for index, record := range records {
		result[index] = RoutedProjectRecord{
			Content: append([]byte(nil), record.Content...),
			Path:    record.Path,
		}
	}
	return result
}

func admitProjectChildRecord(content []byte, route Route, children *admittedProjectChildren) (string, bool) {
	raw, err := admission.DecodeJSON(bytes.NewReader(content), repositorytransaction.MaximumFileBytes)
	if err != nil {
		return "", false
	}
	switch route.ArtifactKind {
	case ArtifactRequirementSource:
		result, err := requirementsourceadmission.Evaluate(raw)
		if err != nil || result.ExitCode != 0 {
			return "", false
		}
		children.sources = append(children.sources, result.Source)
		return result.Source.SourceID, true
	case ArtifactRequirementBinding:
		result, err := requirementbinding.Build(raw)
		if err != nil || result.Record.State != "passed" {
			return "", false
		}
		children.binding = result.Input
		children.bindingPath = route.Path
		return result.Input.BindingID, true
	case ArtifactTestInventory:
		result, err := testevidenceinventory.EvaluateDirect(raw)
		if err != nil || result.ExitCode != 0 {
			return "", false
		}
		children.inventory = result.Inventory
		children.inventoryPath = route.Path
		return result.Inventory.InventoryID, true
	default:
		return "", false
	}
}

func validateMaterializedProjectSnapshot(snapshot materializedProjectSnapshot) error {
	request := Request{
		Binding:       snapshot.Binding,
		BindingPath:   snapshot.BindingPath,
		Inventory:     snapshot.Inventory,
		InventoryPath: snapshot.InventoryPath,
		ProjectID:     snapshot.Manifest.ProjectID,
		RequestID:     snapshot.Manifest.MaterializationRequestID,
		SourcePlanID:  snapshot.Manifest.SourcePlanID,
		Sources:       snapshot.Sources,
	}
	if err := validateClosure(request); err != nil {
		return err
	}
	children, err := childArtifacts(request)
	if err != nil {
		return err
	}
	expected, err := buildManifest(request, children)
	if err != nil {
		return err
	}
	if !sameManifest(snapshot.Manifest, expected) {
		return fmt.Errorf("project routing manifest does not exactly match its materialized children")
	}
	return nil
}

func sameManifest(left, right Manifest) bool {
	return left.ManifestID == right.ManifestID &&
		left.MaterializationRequestID == right.MaterializationRequestID &&
		left.ProjectID == right.ProjectID &&
		left.SourcePlanID == right.SourcePlanID &&
		slices.Equal(left.Routes, right.Routes)
}
