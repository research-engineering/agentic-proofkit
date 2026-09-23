package requirementcontext

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func snapshotStructureCases(t *testing.T) map[string]map[string]any {
	t.Helper()
	root := fixtureRepository(t)
	catalog, err := Compose(root, fixtureCatalog())
	if err != nil {
		t.Fatal(err)
	}
	fixture := newProjectContextFixture(t)
	project, err := FromProject(fixture.inspection.Project, fixture.inspection.ManifestContentDigest)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]map[string]any{"catalog": catalog, "project": SnapshotValue(project)}
}

func TestSnapshotStructuresConserveBothOriginsThroughSlice(t *testing.T) {
	for name, value := range snapshotStructureCases(t) {
		t.Run(name, func(t *testing.T) {
			encoded, err := stablejson.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
			if err != nil {
				t.Fatal(err)
			}
			shaped, err := SnapshotShape().Admit(wire, name)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := AdmitSnapshot(shaped)
			if err != nil {
				t.Fatal(err)
			}
			if !sameStableJSON(t, SnapshotValue(snapshot), value) {
				t.Fatal("snapshot changed during structural roundtrip")
			}
			actual, err := Slice(map[string]any{"schemaVersion": json.Number("2"), "context": shaped, "sliceId": "slice.structure", "query": map[string]any{"profile": "routing"}})
			if err != nil {
				t.Fatal(err)
			}
			expected, err := SliceSnapshot(snapshot, map[string]any{"profile": "routing"}, "slice.structure")
			if err != nil || !sameStableJSON(t, actual, expected) {
				t.Fatalf("whole slice diverged: %v", err)
			}
			if err := catalogSnapshotShape.CheckGenerated(value, name); (err == nil) != (name == "catalog") {
				t.Fatalf("catalog output accepted wrong origin: %v", err)
			}
		})
	}
}

func TestSnapshotStructuresRejectNestedAndOriginConfusion(t *testing.T) {
	for _, mutation := range []string{"null-origin", "catalog-with-origin", "missing-inventory", "old-source", "unknown-manifest-field", "wrong-source-kind", "wrong-source-role", "null-proof", "null-coverage"} {
		t.Run(mutation, func(t *testing.T) {
			values := snapshotStructureCases(t)
			record := values["project"]
			switch mutation {
			case "null-origin":
				record["projectOrigin"] = nil
			case "catalog-with-origin":
				record = values["catalog"]
				record["projectOrigin"] = values["project"]["projectOrigin"]
			case "missing-inventory":
				delete(record["projectOrigin"].(map[string]any), "testEvidenceInventory")
			case "old-source":
				record["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["schemaVersion"] = json.Number("1")
			case "unknown-manifest-field":
				record["projectOrigin"].(map[string]any)["manifest"].(map[string]any)["approval"] = true
			case "wrong-source-kind":
				record["sources"].([]any)[0].(map[string]any)["kind"] = "spec_tree"
			case "wrong-source-role":
				for _, raw := range record["sources"].([]any) {
					if source := raw.(map[string]any); source["kind"] == "requirement_source" {
						source["sourceRole"] = "overview"
						break
					}
				}
			case "null-proof":
				record["projections"].(map[string]any)["proofBinding"] = nil
			case "null-coverage":
				record = values["catalog"]
				record["projections"].(map[string]any)["coverage"] = nil
			}
			if _, err := SnapshotShape().Admit(record, "snapshot"); err == nil {
				t.Fatal("invalid structural variant admitted")
			}
			if _, err := AdmitSnapshot(record); err == nil {
				t.Fatal("native snapshot admitted invalid variant")
			}
		})
	}
}
