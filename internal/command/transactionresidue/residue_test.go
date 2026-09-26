package transactionresidue

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

func TestResidueProjectionUsesNativeObservation(t *testing.T) {
	root := t.TempDir()
	absent, err := Inspect(t.Context(), root)
	if err != nil || absent.state != "absent" || absent.JSONValue()["observationId"] != nil {
		t.Fatalf("absent: %v", err)
	}
	active := filepath.Join(root, ".agentic-proofkit/transactions/active")
	if err := os.MkdirAll(active, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(active, "journal.tmp"), []byte("unprinted bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	native, err := repositorytransaction.InspectPreparationResidue(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	output, err := Inspect(t.Context(), root)
	if err != nil || output.state != native.State || output.observationID != native.ObservationID {
		t.Fatalf("native observation drift: %v", err)
	}
	view := output.JSONValue()
	view["nonClaims"].([]any)[0] = "caller mutation"
	view["state"] = "absent"
	if reflect.DeepEqual(view, output.JSONValue()) || strings.Contains(output.Text(), "caller mutation") {
		t.Fatal("public projection retained mutable aliases")
	}
	relocated, err := Quarantine(t.Context(), root, native.ObservationID)
	if err != nil || relocated.state != "quarantined" || relocated.observationID != native.ObservationID {
		t.Fatalf("native relocation drift: %v", err)
	}
	if _, err := Quarantine(t.Context(), root, native.ObservationID); !errors.Is(err, repositorytransaction.ErrResidueDestinationPresent) {
		t.Fatal("native retry error was reclassified")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if output, err := Inspect(ctx, root); err == nil || output != (Output{}) {
		t.Fatal("native cancellation was classified as success")
	}
	if output, err := Quarantine(t.Context(), filepath.Join(root, "missing"), "invalid"); err == nil || output != (Output{}) {
		t.Fatal("invalid reference became a success")
	}
}

func TestResidueOutputStructuresRejectIndependentMutants(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		kind, state string
		observation any
		shape       jsonshape.Shape
	}{
		{"proofkit.preparation-residue-inspection.v1", "absent", nil, inspectionShape},
		{"proofkit.preparation-residue-inspection.v1", "eligible", id, inspectionShape},
		{"proofkit.preparation-residue-relocation.v1", "quarantined", id, relocationShape},
	} {
		fresh := func() map[string]any {
			return map[string]any{
				"kind": tc.kind, "schemaVersion": json.Number("1"), "state": tc.state, "observationId": tc.observation,
				"nonClaims": []any{
					"A residue observation does not authenticate its producer or establish absence of historical effects.",
					"Quarantine retains evidence; it does not roll back targets, validate their contents, or create a transaction receipt.",
					"These operations do not prove power-loss durability or protection from non-cooperative same-user writers.",
				},
			}
		}
		if _, err := tc.shape.Admit(fresh(), "independent output"); err != nil {
			t.Fatal(err)
		}
		for key := range fresh() {
			v := fresh()
			delete(v, key)
			if _, err := tc.shape.Admit(v, "missing"); err == nil {
				t.Fatalf("missing %s admitted", key)
			}
			v = fresh()
			v[key] = true
			if _, err := tc.shape.Admit(v, "type"); err == nil {
				t.Fatalf("boolean %s admitted", key)
			}
		}
		mutants := map[string]func(map[string]any){
			"unknown":         func(v map[string]any) { v["path"] = "/private" },
			"transaction":     func(v map[string]any) { v["transactionId"] = id },
			"applied-count":   func(v map[string]any) { v["appliedCount"] = json.Number("0") },
			"kind":            func(v map[string]any) { v["kind"] = "proofkit.repository-write-result" },
			"version":         func(v map[string]any) { v["schemaVersion"] = json.Number("2") },
			"lexical-version": func(v map[string]any) { v["schemaVersion"] = json.Number("1.0") },
			"state":           func(v map[string]any) { v["state"] = "applied" },
			"cross-state": func(v map[string]any) {
				if tc.state == "absent" {
					v["observationId"] = id
				} else {
					v["observationId"] = nil
				}
			},
			"short-claims": func(v map[string]any) { v["nonClaims"] = v["nonClaims"].([]any)[:2] },
			"extra-claim":  func(v map[string]any) { v["nonClaims"] = append(v["nonClaims"].([]any), "extra") },
			"claim-order":  func(v map[string]any) { a := v["nonClaims"].([]any); a[0], a[1] = a[1], a[0] },
			"claim-text":   func(v map[string]any) { v["nonClaims"].([]any)[0] = "zero historical effects" },
		}
		for _, ref := range []string{"", "sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("A", 64), id + "\n", "prefix" + id} {
			v := fresh()
			v["observationId"] = ref
			if _, err := tc.shape.Admit(v, "reference"); err == nil {
				t.Fatal("invalid reference admitted")
			}
		}
		for name, change := range mutants {
			v := fresh()
			change(v)
			if _, err := tc.shape.Admit(v, "mutant"); err == nil {
				t.Fatalf("%s/%s admitted", tc.state, name)
			}
		}
	}
	first := InspectionOutputStructure()
	first["oneOf"].([]any)[0].(map[string]any)["additionalProperties"] = true
	if reflect.DeepEqual(first, InspectionOutputStructure()) {
		t.Fatal("inspection schema returned mutable authority")
	}
	first = RelocationOutputStructure()
	first["properties"].(map[string]any)["state"] = map[string]any{"type": "boolean"}
	if reflect.DeepEqual(first, RelocationOutputStructure()) {
		t.Fatal("relocation schema returned mutable authority")
	}
}
