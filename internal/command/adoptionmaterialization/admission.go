package adoptionmaterialization

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func admitRequest(raw any) (Request, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Request{}, fmt.Errorf("adoption materialization request must be an object")
	}
	if err := admit.KnownKeys(record, []string{"nonClaims", "projectId", "requestId", "requestKind", "requirementProofBinding", "requirementSources", "schemaVersion", "sourcePlan", "testEvidenceInventory"}, "adoption materialization request"); err != nil {
		return Request{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], SchemaVersion) || record["requestKind"] != RequestKind {
		return Request{}, fmt.Errorf("adoption materialization request identity is invalid")
	}
	requestID, err := admit.RuleID(record["requestId"], "adoption materialization requestId")
	if err != nil {
		return Request{}, err
	}
	projectID, err := admit.RuleID(record["projectId"], "adoption materialization projectId")
	if err != nil {
		return Request{}, err
	}
	sourcePlan, err := adoptionplan.AdmitOutput(record["sourcePlan"])
	if err != nil {
		return Request{}, err
	}
	sourcePlanID, sourceIntent := sourcePlanCoordinates(sourcePlan)
	sources, err := admitSources(record["requirementSources"])
	if err != nil {
		return Request{}, err
	}
	bindingPath, binding, err := admitBindingArtifact(record["requirementProofBinding"])
	if err != nil {
		return Request{}, err
	}
	inventoryPath, inventory, err := admitInventoryArtifact(record["testEvidenceInventory"])
	if err != nil {
		return Request{}, err
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "adoption materialization nonClaims", true)
	if err != nil {
		return Request{}, err
	}
	request := Request{
		Binding: binding, BindingPath: bindingPath, Inventory: inventory, InventoryPath: inventoryPath,
		NonClaims: nonClaims, ProjectID: projectID, RequestID: requestID, SourceIntent: sourceIntent,
		SourcePlanID: sourcePlanID, Sources: sources,
	}
	if err := validateClosure(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

func admitSources(raw any) ([]requirementsourceadmission.Source, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 || len(values) > MaximumRequirementSources {
		return nil, fmt.Errorf("adoption materialization requirementSources count is invalid")
	}
	sources := make([]requirementsourceadmission.Source, 0, len(values))
	for _, value := range values {
		result, err := requirementsourceadmission.Evaluate(value)
		if err != nil {
			return nil, err
		}
		if result.ExitCode != 0 {
			return nil, fmt.Errorf("adoption materialization requires passed requirement source admission")
		}
		sources = append(sources, result.Source)
	}
	sort.Slice(sources, func(left, right int) bool { return sources[left].RequirementsPath < sources[right].RequirementsPath })
	return sources, nil
}

func admitBindingArtifact(raw any) (string, requirementbinding.Input, error) {
	path, child, err := admitArtifactWrapper(raw, "requirementProofBinding")
	if err != nil {
		return "", requirementbinding.Input{}, err
	}
	result, err := requirementbinding.Build(child)
	if err != nil {
		return "", requirementbinding.Input{}, err
	}
	if result.Record.State != "passed" {
		return "", requirementbinding.Input{}, fmt.Errorf("adoption materialization requires passed requirement proof binding admission")
	}
	return path, result.Input, nil
}

func admitInventoryArtifact(raw any) (string, testevidenceinventory.Inventory, error) {
	path, child, err := admitArtifactWrapper(raw, "testEvidenceInventory")
	if err != nil {
		return "", testevidenceinventory.Inventory{}, err
	}
	result, err := testevidenceinventory.EvaluateDirect(child)
	if err != nil {
		return "", testevidenceinventory.Inventory{}, err
	}
	if result.ExitCode != 0 {
		return "", testevidenceinventory.Inventory{}, fmt.Errorf("adoption materialization requires passed direct test evidence inventory admission")
	}
	return path, result.Inventory, nil
}

func admitArtifactWrapper(raw any, context string) (string, any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("adoption materialization %s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"path", "record"}, "adoption materialization "+context); err != nil {
		return "", nil, err
	}
	pathText, err := admit.NonEmptyText(record["path"], "adoption materialization "+context+" path")
	if err != nil {
		return "", nil, err
	}
	path, err := admit.SafeRepoRelativePath(pathText, "adoption materialization "+context+" path")
	if err != nil {
		return "", nil, err
	}
	child, ok := record["record"]
	if !ok {
		return "", nil, fmt.Errorf("adoption materialization %s record is required", context)
	}
	return path, child, nil
}
