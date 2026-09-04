package adoptionmaterialization

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func TestPathRoleLedgerRejectsWriteReferenceCollisions(t *testing.T) {
	tests := []struct {
		name string
		uses []pathUse
	}{
		{
			name: "overview and binding target",
			uses: []pathUse{
				{Path: "docs/specs/core/overview.md", Role: roleOverviewReference},
				{Path: "docs/specs/core/overview.md", Role: roleBindingTarget, Target: true},
			},
		},
		{
			name: "portable target alias",
			uses: []pathUse{
				{Path: "proofkit/Inventory.json", Role: roleInventoryTarget, Target: true},
				{Path: "proofkit/inventory.json", Role: roleBindingTarget, Target: true},
			},
		},
		{
			name: "reserved namespace reference",
			uses: []pathUse{{Path: ".agentic-proofkit/witness.go", Role: roleWitnessSourceReference}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validatePathRoles(test.uses); err == nil {
				t.Fatal("validatePathRoles() admitted an incompatible path-role relation")
			}
		})
	}
	if err := validatePathRoles([]pathUse{
		{Path: "docs/specs/core/requirements.v1.json", Role: roleRequirementSource, Target: true},
		{Path: "docs/specs/core/requirements.v1.json", Role: roleRequirementSpecRef},
		{Path: "internal/core/core_test.go", Role: roleWitnessSourceReference},
		{Path: "internal/core/core_test.go", Role: roleTestSourceReference},
	}); err != nil {
		t.Fatalf("validatePathRoles() rejected compatible owner paths: %v", err)
	}
}

func TestInventoryReferencesMustResolveThroughBindingEdges(t *testing.T) {
	bindings := []requirementbinding.Binding{
		{RequirementID: "REQ-A", WitnessID: "witness.a", WitnessPath: "a_test.go", CommandIDs: []string{"command.a"}},
		{RequirementID: "REQ-B", WitnessID: "witness.b", WitnessPath: "b_test.go", CommandIDs: []string{"command.b"}},
	}
	requirements := map[string]requirementsourceadmission.Requirement{
		"REQ-A": {RequirementID: "REQ-A"},
		"REQ-B": {RequirementID: "REQ-B"},
	}
	request := Request{
		Binding: requirementbinding.Input{Bindings: bindings},
		Inventory: testevidenceinventory.Inventory{Entries: []testevidenceinventory.Entry{{
			RequirementRefs: []string{"REQ-A"},
			WitnessRefs:     []string{"witness.b"},
			CommandRefs:     []string{"command.b"},
			SourcePath:      "b_test.go",
		}}},
	}
	if err := validateInventoryReferences(request, requirements); err == nil {
		t.Fatal("validateInventoryReferences() admitted globally known but disconnected references")
	}
	request.Inventory.Entries[0] = testevidenceinventory.Entry{
		RequirementRefs: []string{"REQ-A", "REQ-B"},
		WitnessRefs:     []string{"witness.a", "witness.b"},
		CommandRefs:     []string{"command.a", "command.b"},
		SourcePath:      "a_test.go",
	}
	if err := validateInventoryReferences(request, requirements); err == nil {
		t.Fatal("validateInventoryReferences() admitted witnesses from incompatible source paths")
	}
	request.Binding.Bindings[0].WitnessPath = "shared_test.go"
	request.Binding.Bindings[1].WitnessPath = "shared_test.go"
	request.Inventory.Entries[0].SourcePath = "shared_test.go"
	if err := validateInventoryReferences(request, requirements); err != nil {
		t.Fatalf("validateInventoryReferences() rejected a connected shared witness source: %v", err)
	}
}

func TestManifestAdmissionEqualsProducerImage(t *testing.T) {
	tests := []struct {
		name   string
		routes []Route
	}{
		{
			name: "missing inventory",
			routes: []Route{
				{ArtifactID: "source.a", ArtifactKind: ArtifactRequirementSource, Path: "docs/specs/a/requirements.v1.json"},
				{ArtifactID: "source.b", ArtifactKind: ArtifactRequirementSource, Path: "docs/specs/b/requirements.v1.json"},
				{ArtifactID: "binding", ArtifactKind: ArtifactRequirementBinding, Path: "proofkit/binding.json"},
			},
		},
		{
			name: "duplicate artifact identity",
			routes: []Route{
				{ArtifactID: "duplicate", ArtifactKind: ArtifactRequirementSource, Path: "docs/specs/a/requirements.v1.json"},
				{ArtifactID: "duplicate", ArtifactKind: ArtifactRequirementBinding, Path: "proofkit/binding.json"},
				{ArtifactID: "inventory", ArtifactKind: ArtifactTestInventory, Path: "proofkit/inventory.json"},
			},
		},
		{
			name: "requirement source outside producer route language",
			routes: []Route{
				{ArtifactID: "source", ArtifactKind: ArtifactRequirementSource, Path: "docs/specs/arbitrary.json"},
				{ArtifactID: "binding", ArtifactKind: ArtifactRequirementBinding, Path: "proofkit/binding.json"},
				{ArtifactID: "inventory", ArtifactKind: ArtifactTestInventory, Path: "proofkit/inventory.json"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := Manifest{
				MaterializationRequestID: "request",
				ProjectID:                "project",
				Routes:                   test.routes,
				SourcePlanID:             "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			}
			manifest.ManifestID, _ = digest.StableJSONSHA256Ref(manifest.identityValue())
			if _, err := AdmitManifest(manifest.JSONValue()); err == nil {
				t.Fatal("AdmitManifest() admitted a record outside the producer image")
			}
		})
	}
}
