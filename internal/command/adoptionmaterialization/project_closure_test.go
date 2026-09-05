package adoptionmaterialization

import (
	"bytes"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func TestMaterializedProjectClosureIsDeterministic(t *testing.T) {
	snapshot := validMaterializedProjectSnapshot(t)
	for iteration := 0; iteration < 2; iteration++ {
		if err := validateMaterializedProjectSnapshot(snapshot); err != nil {
			t.Fatalf("validateMaterializedProjectSnapshot() iteration %d error = %v", iteration, err)
		}
	}
}

func TestMaterializedProjectRecordSnapshotDoesNotAliasCallerInput(t *testing.T) {
	content := []byte("owner bytes")
	records := []RoutedProjectRecord{{Content: content, Path: "docs/specs/owner/requirements.v1.json"}}
	snapshot := snapshotRoutedProjectRecords(records)

	content[0] = 'X'
	records[0].Content[1] = 'Y'
	records[0].Path = "changed"
	if got := string(snapshot[0].Content); got != "owner bytes" || snapshot[0].Path != "docs/specs/owner/requirements.v1.json" {
		t.Fatalf("snapshot aliases caller-owned records: %#v", snapshot[0])
	}
}

func TestMaterializedProjectClosureRejectsCrossInconsistentChildren(t *testing.T) {
	t.Run("binding projection", func(t *testing.T) {
		snapshot := validMaterializedProjectSnapshot(t)
		raw := requirementbinding.InputValue(snapshot.Binding)
		raw["requirements"].([]any)[0].(map[string]any)["ownerId"] = "different.owner"
		result, err := requirementbinding.Build(raw)
		if err != nil || result.Record.State != "passed" {
			t.Fatalf("independent binding admission failed: result=%#v error=%v", result, err)
		}
		snapshot.Binding = result.Input
		if err := validateMaterializedProjectSnapshot(snapshot); err == nil {
			t.Fatal("validateMaterializedProjectSnapshot() admitted a binding that contradicted its source owner")
		}
	})

	t.Run("inventory route", func(t *testing.T) {
		snapshot := validMaterializedProjectSnapshot(t)
		snapshot.Inventory.Entries[0].RequirementRefs = []string{"REQ-OTHER-001"}
		result, err := testevidenceinventory.EvaluateDirect(testevidenceinventory.InventoryValue(snapshot.Inventory))
		if err != nil || result.ExitCode != 0 {
			t.Fatalf("independent inventory admission failed: result=%#v error=%v", result, err)
		}
		if err := validateMaterializedProjectSnapshot(snapshot); err == nil {
			t.Fatal("validateMaterializedProjectSnapshot() admitted an inventory reference outside its binding")
		}
	})
}

func TestMaterializedProjectClosureRejectsManifestRouteDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{
			name: "path",
			mutate: func(manifest *Manifest) {
				for index := range manifest.Routes {
					if manifest.Routes[index].ArtifactKind == ArtifactRequirementBinding {
						manifest.Routes[index].Path = "proofkit/alternate-bindings.json"
					}
				}
			},
		},
		{
			name: "kind",
			mutate: func(manifest *Manifest) {
				bindingIndex, inventoryIndex := -1, -1
				for index, route := range manifest.Routes {
					switch route.ArtifactKind {
					case ArtifactRequirementBinding:
						bindingIndex = index
					case ArtifactTestInventory:
						inventoryIndex = index
					}
				}
				manifest.Routes[bindingIndex].ArtifactKind, manifest.Routes[inventoryIndex].ArtifactKind =
					manifest.Routes[inventoryIndex].ArtifactKind, manifest.Routes[bindingIndex].ArtifactKind
			},
		},
		{
			name: "artifact identity",
			mutate: func(manifest *Manifest) {
				for index := range manifest.Routes {
					if manifest.Routes[index].ArtifactKind == ArtifactRequirementBinding {
						manifest.Routes[index].ArtifactID = digest.SHA256BytesRef([]byte("different binding bytes"))
					}
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := validMaterializedProjectSnapshot(t)
			snapshot.Manifest = readmitManifest(t, snapshot.Manifest, test.mutate)
			if err := validateMaterializedProjectSnapshot(snapshot); err == nil {
				t.Fatal("validateMaterializedProjectSnapshot() admitted manifest route drift")
			}
		})
	}
}

func TestMaterializedProjectClosureRejectsMissingAndSurplusSources(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		snapshot := validMaterializedProjectSnapshot(t)
		snapshot.Sources = nil
		if err := validateMaterializedProjectSnapshot(snapshot); err == nil {
			t.Fatal("validateMaterializedProjectSnapshot() admitted a missing requirement source")
		}
	})

	t.Run("surplus", func(t *testing.T) {
		snapshot := validMaterializedProjectSnapshot(t)
		raw := requirementsourceadmission.SourceValue(snapshot.Sources[0])
		raw["sourceId"] = "surplus.requirements"
		raw["specPackagePath"] = "docs/specs/surplus"
		raw["overviewPath"] = "docs/specs/surplus/overview.md"
		raw["requirementsPath"] = "docs/specs/surplus/requirements.v1.json"
		requirement := raw["requirements"].([]any)[0].(map[string]any)
		requirement["requirementId"] = "REQ-SURPLUS-001"
		result, err := requirementsourceadmission.Evaluate(raw)
		if err != nil || result.ExitCode != 0 {
			t.Fatalf("independent source admission failed: result=%#v error=%v", result, err)
		}
		snapshot.Sources = append(snapshot.Sources, result.Source)
		if err := validateMaterializedProjectSnapshot(snapshot); err == nil {
			t.Fatal("validateMaterializedProjectSnapshot() admitted a source absent from the manifest")
		}
	})
}

func TestAdmitMaterializedProjectRejectsConstructedManifestIdentityDrift(t *testing.T) {
	snapshot := validMaterializedProjectSnapshot(t)
	manifest := snapshot.Manifest
	manifest.ProjectID = "different.project"
	if _, err := AdmitMaterializedProject(manifest, nil); err == nil {
		t.Fatal("AdmitMaterializedProject() admitted caller-constructed manifest identity drift")
	}
}

func TestAdmitMaterializedProjectRoutesEveryManifestArtifactKindThroughItsOwner(t *testing.T) {
	request, err := admitRequest(validRequest(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := childArtifacts(request)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := buildManifest(request, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	records := make([]RoutedProjectRecord, 0, len(artifacts))
	for _, artifact := range artifacts {
		records = append(records, RoutedProjectRecord{Content: artifact.Content, Path: artifact.Path})
	}
	result, err := AdmitMaterializedProject(manifest, records)
	if err != nil || !result.ClosureEvaluated || !result.ClosureAdmitted || len(result.Records) != len(manifest.Routes) {
		t.Fatalf("AdmitMaterializedProject()=%#v, %v", result, err)
	}
	for _, item := range result.Records {
		if !item.DigestMatches || !item.Admitted {
			t.Fatalf("route %s was not owner-admitted: %#v", item.Path, item)
		}
	}

	for index := range records {
		kind := "unknown"
		for _, route := range manifest.Routes {
			if route.Path == records[index].Path {
				kind = route.ArtifactKind
			}
		}
		t.Run(kind+"/digest_mismatch", func(t *testing.T) {
			mutant := append([]RoutedProjectRecord(nil), records...)
			mutant[index].Content = bytes.Repeat([]byte{'x'}, len(mutant[index].Content))
			got, err := AdmitMaterializedProject(manifest, mutant)
			var routeAdmission RoutedProjectRecordAdmission
			for _, item := range got.Records {
				if item.Path == mutant[index].Path {
					routeAdmission = item
				}
			}
			if err != nil || got.ClosureEvaluated || got.ClosureAdmitted || routeAdmission.DigestMatches || routeAdmission.Admitted {
				t.Fatalf("mutated route admission=%#v, %v", got, err)
			}
		})

		t.Run(kind+"/semantic_owner_rejection", func(t *testing.T) {
			invalidContent := []byte("{}")
			mutant := append([]RoutedProjectRecord(nil), records...)
			mutant[index].Content = invalidContent
			mutantManifest := readmitManifest(t, manifest, func(candidate *Manifest) {
				for routeIndex := range candidate.Routes {
					if candidate.Routes[routeIndex].Path == mutant[index].Path {
						candidate.Routes[routeIndex].ArtifactID = digest.SHA256BytesRef(invalidContent)
					}
				}
			})
			got, err := AdmitMaterializedProject(mutantManifest, mutant)
			var routeAdmission RoutedProjectRecordAdmission
			for _, item := range got.Records {
				if item.Path == mutant[index].Path {
					routeAdmission = item
				}
			}
			if err != nil || got.ClosureEvaluated || got.ClosureAdmitted || !routeAdmission.DigestMatches || routeAdmission.Admitted {
				t.Fatalf("semantically invalid route admission=%#v, %v", got, err)
			}
		})
	}
}

func TestAdmitMaterializedProjectRejectsSurplusAndDuplicateRoutes(t *testing.T) {
	snapshot := validMaterializedProjectSnapshot(t)
	record := RoutedProjectRecord{Path: snapshot.Manifest.Routes[0].Path}
	if _, err := AdmitMaterializedProject(snapshot.Manifest, []RoutedProjectRecord{record, record}); err == nil {
		t.Fatal("AdmitMaterializedProject() admitted duplicate record paths")
	}
	record.Path = "proofkit/unrouted.json"
	if _, err := AdmitMaterializedProject(snapshot.Manifest, []RoutedProjectRecord{record}); err == nil {
		t.Fatal("AdmitMaterializedProject() admitted an unmanifested record path")
	}
}

func validMaterializedProjectSnapshot(t *testing.T) materializedProjectSnapshot {
	t.Helper()
	request, err := admitRequest(validRequest(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	children, err := childArtifacts(request)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := buildManifest(request, children)
	if err != nil {
		t.Fatal(err)
	}
	return materializedProjectSnapshot{
		Binding: request.Binding, BindingPath: request.BindingPath,
		Inventory: request.Inventory, InventoryPath: request.InventoryPath,
		Manifest: manifest, Sources: request.Sources,
	}
}

func readmitManifest(t *testing.T, manifest Manifest, mutate func(*Manifest)) Manifest {
	t.Helper()
	manifest.Routes = append([]Route(nil), manifest.Routes...)
	mutate(&manifest)
	manifest.ManifestID = ""
	manifestID, err := digest.StableJSONSHA256Ref(manifest.identityValue())
	if err != nil {
		t.Fatal(err)
	}
	manifest.ManifestID = manifestID
	admitted, err := AdmitManifest(manifest.JSONValue())
	if err != nil {
		t.Fatalf("independent manifest admission failed: %v", err)
	}
	return admitted
}
