package projectfixture

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"os"
	"path/filepath"
	"testing"
)

//go:embed testdata/source.json
var sourceSeed []byte

type Fixture struct {
	Root    string
	Files   map[string][]byte
	Project map[string]any
}

// New arranges a disposable project, never an expected browser projection.
func New(t testing.TB) Fixture {
	t.Helper()
	return WithRequirementIDs(t, [3]string{"REQ-WIRE-001", "REQ-WIRE-002", "REQ-WIRE-003"})
}

// WithRequirementIDs varies only admitted source identities in the same fixture.
func WithRequirementIDs(t testing.TB, ids [3]string) Fixture {
	t.Helper()
	seed := sourceSeed
	sources, requirements, bindings, entries := []any{}, []any{}, []any{}, []any{}
	files := map[string][]byte{}
	for index, item := range []struct{ id, directory, text string }{{"zeta.source", "a", "Collection \U0001f9ed A preserves its explicit invariant."}, {"shared.identity", "z", "Collection E\u0301 Z preserves its explicit invariant."}} {
		source := record(t, seed)
		path := "docs/specs/" + item.directory + "/requirements.v1.json"
		source["sourceId"], source["specPackagePath"], source["overviewPath"], source["requirementsPath"] = item.id, "docs/specs/"+item.directory, "docs/specs/"+item.directory+"/overview.md", path
		source["nonClaims"] = []any{"Source " + item.directory + " does not prove execution."}
		items := source["requirements"].([]any)
		if index == 1 {
			items = append(items, clone(t, items[0].(map[string]any)))
		}
		for position, raw := range items {
			requirement := raw.(map[string]any)
			number := index + position + 1
			id := ids[number-1]
			requirement["requirementId"], requirement["invariant"] = id, item.text
			requirement["nonClaimRefs"] = []any{"collection.nonclaim.execution"}
			suffix := fmt.Sprintf("%03d", number)
			requirements = append(requirements, map[string]any{"requirementId": id, "ownerId": "wire.owner", "specPath": path, "claimLevel": "blocking", "proofState": "witness_backed", "nonClaims": requirement["nonClaims"]})
			bindings = append(bindings, map[string]any{"requirementId": id, "scenarioId": "collection.scenario." + suffix, "witnessId": "collection.witness." + suffix, "witnessKind": "contract", "witnessPath": "tests/collection_test.go", "witnessSelectors": []any{map[string]any{"selector": "TestCollection" + suffix, "command": "go test ./tests -run TestCollection" + suffix}}, "commandIds": []any{"collection.check"}, "environmentClasses": []any{"local-go"}})
			entries = append(entries, map[string]any{
				"testId": "collection.test." + suffix, "selector": "go test ./tests -run TestCollection" + suffix, "sourcePath": "tests/collection_test.go", "ownerId": "wire.owner",
				"evidenceClass": "declared_semantic_falsifier_route", "requirementRefs": []any{id}, "ownerInvariantRefs": []any{}, "commandRefs": []any{"collection.check"}, "witnessRefs": []any{"collection.witness." + suffix},
				"falsifier": map[string]any{"falsifierId": "collection.falsifier." + suffix, "negativeCaseId": "collection.case." + suffix, "wrongImplementationClassId": "collection.wrong." + suffix, "dominanceGroup": "collection.group." + suffix, "supersedes": []any{}},
				"oracle":    map[string]any{"oracleId": "collection.oracle." + suffix, "oracleKind": "negative_exit_and_diagnostic", "expectedPublicOutcome": "invalid collection fails", "assertionSummary": "A contradictory collection is rejected."}, "nonClaims": []any{},
			})
		}
		source["requirements"] = items
		admitted, err := requirementsourceadmission.Evaluate(source)
		if err != nil || admitted.ExitCode != 0 {
			t.Fatalf("independent source fixture: %v", err)
		}
		canonical := requirementsourceadmission.SourceValue(admitted.Source)
		sources = append(sources, canonical)
		files[path] = jsonBytes(t, canonical)
	}
	binding, err := requirementbinding.Build(map[string]any{
		"schemaVersion": json.Number("1"), "bindingId": "shared.identity", "requirements": requirements, "bindings": bindings,
		"selection":       map[string]any{"changedPaths": []any{}, "ownerIds": []any{}, "requirementIds": []any{}},
		"witnessCommands": []any{map[string]any{"commandId": "collection.check", "command": "go test ./tests", "environmentClasses": []any{"local-go"}}},
		"nonClaims":       []any{"Collection bindings do not execute witnesses."},
	})
	if err != nil || binding.Record.State != "passed" {
		t.Fatalf("independent binding fixture: %v", err)
	}
	inventory, err := testevidenceinventory.EvaluateDirect(map[string]any{
		"schemaVersion": json.Number("1"), "inventoryId": "shared.identity", "authority": "caller_owned_inventory", "entries": entries,
		"sourceId": "collection.inventory", "ownerId": "wire.owner",
		"nonClaims": []any{"Collection inventory does not establish execution."},
	})
	if err != nil || inventory.ExitCode != 0 {
		t.Fatalf("independent inventory fixture: %v", err)
	}
	bindingValue, inventoryValue := requirementbinding.InputValue(binding.Input), testevidenceinventory.InventoryValue(inventory.Inventory)
	files["proofkit/bindings.json"], files["proofkit/tests.json"] = jsonBytes(t, bindingValue), jsonBytes(t, inventoryValue)
	routes := []any{}
	for _, item := range []struct{ kind, path string }{
		{"requirement_source", "docs/specs/a/requirements.v1.json"}, {"requirement_source", "docs/specs/z/requirements.v1.json"},
		{"requirement_proof_binding", "proofkit/bindings.json"}, {"test_evidence_inventory", "proofkit/tests.json"},
	} {
		routes = append(routes, map[string]any{"artifactId": contentDigest(files[item.path]), "artifactKind": item.kind, "path": item.path})
	}
	manifest := map[string]any{
		"schemaVersion": json.Number("1"), "authority": "routing_only", "manifestKind": "proofkit.project-routing-manifest",
		"materializationRequestId": "collection.request", "projectId": "shared.identity", "sourcePlanId": contentDigest([]byte("collection source plan")), "routes": routes,
		"nonClaims": []any{"Project routing manifests do not duplicate child semantics or prove child admission, freshness, execution, merge, release, rollout, or production readiness."},
	}
	manifest["manifestId"] = contentDigest(jsonBytes(t, manifest))
	// Captured manifest bytes intentionally differ from canonical JSON bytes.
	files[adoptionmaterialization.ProjectManifestPath] = append([]byte(" \n"), jsonBytes(t, manifest)...)
	root := t.TempDir()
	for path, content := range files {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return Fixture{Root: root, Files: files, Project: map[string]any{
		"manifest": manifest, "requirementSources": sources, "proofBinding": bindingValue, "testEvidenceInventory": inventoryValue,
	}}
}

func record(t testing.TB, content []byte) map[string]any {
	t.Helper()
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}

func clone(t testing.TB, value map[string]any) map[string]any {
	t.Helper()
	return record(t, jsonBytes(t, value))
}

func jsonBytes(t testing.TB, value any) []byte {
	t.Helper()
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func contentDigest(content []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(content))
}
