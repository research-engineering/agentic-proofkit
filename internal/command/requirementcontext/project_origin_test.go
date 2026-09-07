package requirementcontext

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/command/projectstatus"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/projectfixture"
)

type projectContextFixture struct {
	inspection projectstatus.Inspection
	original   map[string]any
	files      map[string][]byte
}

func TestProjectContextCaptureWireAdmissionAndSlice(t *testing.T) {
	fixture := newProjectContextFixture(t)
	snapshot, err := FromProject(fixture.inspection.Project, fixture.inspection.ManifestContentDigest)
	if err != nil {
		t.Fatal(err)
	}
	actual := SnapshotValue(snapshot)
	expected := expectedProjectContext(t, fixture)
	if !bytes.Equal(projectTestJSON(t, actual), projectTestJSON(t, expected)) {
		for key, want := range expected {
			if !bytes.Equal(projectTestJSON(t, actual[key]), projectTestJSON(t, want)) {
				t.Logf("different wire field: %s", key)
			}
		}
		t.Fatal("project context differs from the independent complete projection")
	}
	admitted, err := AdmitSnapshot(predecessorRecord(t, projectTestJSON(t, actual)))
	if err != nil || !bytes.Equal(projectTestJSON(t, SnapshotValue(admitted)), projectTestJSON(t, expected)) {
		t.Fatalf("project context did not survive wire re-admission: %v", err)
	}
	if snapshot.Coverage != nil || snapshot.ExpectedDigestCoverage != "partial" {
		t.Fatal("project inventory became coverage or fabricated full expected-digest coverage")
	}
	for _, test := range []struct {
		id, text, pointer, path string
	}{
		{"REQ-WIRE-001", "Collection \U0001f9ed A preserves its explicit invariant.", "/projections/requirementSources/1/requirements/0/invariant", "docs/specs/a/requirements.v1.json"},
		{"REQ-WIRE-002", "Collection E\u0301 Z preserves its explicit invariant.", "/projections/requirementSources/0/requirements/0/invariant", "docs/specs/z/requirements.v1.json"},
	} {
		t.Run(test.id, func(t *testing.T) {
			pointer, err := jsonpointer.Parse(test.pointer)
			if err != nil {
				t.Fatal(err)
			}
			text, err := jsonpointer.SelectParsed(actual, pointer)
			if err != nil || text != test.text {
				t.Fatalf("source-ordered pointer resolved to a different invariant: %v", err)
			}
			slice, err := SliceSnapshot(admitted, map[string]any{"profile": "review", "requirementIds": []any{test.id}, "maxRequirements": json.Number("1")}, "collection.slice")
			if err != nil {
				t.Fatal(err)
			}
			fragments := slice["projections"].(map[string]any)["requirementSources"].([]any)
			if len(fragments) != 1 {
				t.Fatal("slice included an unselected source")
			}
			fragment := fragments[0].(map[string]any)
			original := predecessorRecord(t, fixture.files[test.path])
			if !reflect.DeepEqual(fragment["nonClaims"], original["nonClaims"]) {
				t.Fatal("source-level restrictions were lost or taken from a different source")
			}
			requirements := fragment["requirements"].([]any)
			if len(requirements) != 1 || !reflect.DeepEqual(requirements[0], original["requirements"].([]any)[0]) {
				t.Fatal("selected invariant or its separate metadata was lost")
			}
			if fragment["omittedRequirementCount"] != len(original["requirements"].([]any))-1 {
				t.Fatal("source omissions differ from the original source")
			}
			matched := 0
			for _, source := range admitted.Sources {
				if source.Kind == "requirement_source" && source.SourceRef == original["sourceId"] {
					matched++
					if source.Path != test.path || source.CurrentDigest != projectTestDigest(fixture.files[test.path]) {
						t.Fatal("source ID/path ordering changed the physical digest association")
					}
				}
			}
			if matched != 1 {
				t.Fatal("typed requirement source did not resolve exactly once")
			}
		})
	}
}

func TestProjectContextNormalizesEquivalentSourceOrders(t *testing.T) {
	fixture := newProjectContextFixture(t)
	expected := expectedProjectContext(t, fixture)
	reordered := deepClone(t, expected)
	for _, values := range [][]any{reordered["sources"].([]any), reordered["projections"].(map[string]any)["requirementSources"].([]any)} {
		for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
			values[left], values[right] = values[right], values[left]
		}
	}
	snapshot, err := AdmitSnapshot(reordered)
	if err != nil || !bytes.Equal(projectTestJSON(t, SnapshotValue(snapshot)), projectTestJSON(t, expected)) {
		t.Fatalf("equivalent project source order changed identity: %v", err)
	}
}

func TestProjectContextRejectsInvalidOriginAndSourcePartition(t *testing.T) {
	base := expectedProjectContext(t, newProjectContextFixture(t))
	for name, mutate := range map[string]func(map[string]any){
		"old version":                   func(v map[string]any) { v["schemaVersion"] = json.Number("2") },
		"future version":                func(v map[string]any) { v["schemaVersion"] = json.Number("4") },
		"wrong kind":                    func(v map[string]any) { v["contextKind"] = "different.context" },
		"missing origin":                func(v map[string]any) { delete(v, "projectOrigin") },
		"missing inventory":             func(v map[string]any) { delete(v["projectOrigin"].(map[string]any), "testEvidenceInventory") },
		"extra origin field":            func(v map[string]any) { v["projectOrigin"].(map[string]any)["unknown"] = true },
		"wrong identity":                func(v map[string]any) { v["snapshotId"] = "sha256:" + strings.Repeat("0", 64) },
		"fabricated coverage":           func(v map[string]any) { v["projections"].(map[string]any)["coverage"] = map[string]any{} },
		"invented full digest coverage": func(v map[string]any) { v["expectedDigestCoverage"] = "all" },
		"missing physical inventory":    func(v map[string]any) { v["sources"] = v["sources"].([]any)[:4] },
		"fabricated tree file":          func(v map[string]any) { v["sources"].([]any)[0].(map[string]any)["kind"] = "spec_tree" },
		"wrong source role":             func(v map[string]any) { v["sources"].([]any)[2].(map[string]any)["sourceRole"] = "overview" },
		"wrong source node": func(v map[string]any) {
			v["sources"].([]any)[2].(map[string]any)["nodeId"] = "different.root"
			resignProjectContext(t, v)
		},
		"manifest expected digest": func(v map[string]any) {
			row := v["sources"].([]any)[0].(map[string]any)
			row["expectedDigest"] = row["currentDigest"]
			resignProjectContext(t, v)
		},
		"child digest not from route": func(v map[string]any) {
			row := v["sources"].([]any)[1].(map[string]any)
			row["currentDigest"], row["expectedDigest"] = projectTestDigest(nil), projectTestDigest(nil)
			resignProjectContext(t, v)
		},
		"duplicate composite key": func(v map[string]any) {
			row := deepClone(t, v["sources"].([]any)[0].(map[string]any))
			row["path"] = "proofkit/another.json"
			v["sources"] = append(v["sources"].([]any), row)
		},
		"duplicate path": func(v map[string]any) {
			row := deepClone(t, v["sources"].([]any)[0].(map[string]any))
			row["sourceRef"] = "another.binding"
			v["sources"] = append(v["sources"].([]any), row)
		},
		"lost source restriction": func(v map[string]any) {
			v["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["nonClaims"] = []any{}
		},
		"different catalog": func(v map[string]any) { v["catalogId"] = "another.project"; resignProjectContext(t, v) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := deepClone(t, base)
			mutate(candidate)
			if _, err := AdmitSnapshot(candidate); err == nil {
				t.Fatal("invalid project context was admitted")
			}
		})
	}
}

func TestProjectContextRejectsResignedUnrelatedTree(t *testing.T) {
	base := expectedProjectContext(t, newProjectContextFixture(t))
	origin := base["projectOrigin"].(map[string]any)
	manifest := origin["manifest"].(map[string]any)
	manifest["projectId"] = "another.project"
	delete(manifest, "manifestId")
	manifest["manifestId"] = projectTestDigest(projectTestJSON(t, manifest))
	base["catalogId"] = "another.project"
	physical := base["sources"].([]any)[0].(map[string]any)
	physical["sourceRef"] = "another.project"
	physical["currentDigest"] = projectTestDigest(projectTestJSON(t, manifest))
	resignProjectContext(t, base)
	if _, err := AdmitSnapshot(base); err == nil || !strings.Contains(err.Error(), "derived collection") {
		t.Fatalf("resigned project retaining the old tree label must fail owner replay: %v", err)
	}
	base["projections"].(map[string]any)["specTree"].(map[string]any)["nodes"].([]any)[0].(map[string]any)["label"] = "another.project"
	resignProjectContext(t, base)
	if _, err := AdmitSnapshot(base); err != nil {
		t.Fatalf("the otherwise identical correct collection was rejected: %v", err)
	}
}

func TestProjectContextRejectsZeroProjectAndOversizeBeforeReplay(t *testing.T) {
	for _, project := range []*adoptionmaterialization.Project{nil, {}} {
		if _, err := FromProject(project, projectTestDigest(nil)); err == nil {
			t.Fatal("zero project acquired context authority")
		}
	}
	base := expectedProjectContext(t, newProjectContextFixture(t))
	base["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)[0].(map[string]any)["invariant"] = strings.Repeat("a", maxSnapshotBytes)
	if _, err := AdmitSnapshot(base); err == nil || !strings.Contains(err.Error(), "byte boundary") {
		t.Fatalf("oversize input reached child replay: %v", err)
	}
}

func expectedProjectContext(t *testing.T, fixture projectContextFixture) map[string]any {
	t.Helper()
	sources := fixture.original["requirementSources"].([]any)
	projections := map[string]any{
		"requirementSources": []any{sources[1], sources[0]},
		"proofBinding":       fixture.original["proofBinding"],
		"specTree": map[string]any{
			"schemaVersion": json.Number("2"), "treeId": "project.collection", "rootNodeId": "project.root",
			"callerAnnotations": []any{"This collection is routing-only and does not infer product hierarchy."},
			"edges":             []any{}, "overlays": []any{},
			"nodes": []any{map[string]any{
				"callerAnnotations": []any{}, "displayOrder": json.Number("1"), "label": "shared.identity", "nodeId": "project.root", "nodeKind": "meta_spec",
				"sourceRefs": []any{
					map[string]any{"sourceRefId": "shared.identity", "sourceRefKind": "source_id", "sourceRole": "requirements", "sourceId": "shared.identity"},
					map[string]any{"sourceRefId": "zeta.source", "sourceRefKind": "source_id", "sourceRole": "requirements", "sourceId": "zeta.source"},
				},
			}},
		},
	}
	physical := []any{}
	for _, row := range []struct{ kind, id, path string }{
		{"project_manifest", "shared.identity", adoptionmaterialization.ProjectManifestPath},
		{"proof_binding", "shared.identity", "proofkit/bindings.json"},
		{"requirement_source", "shared.identity", "docs/specs/z/requirements.v1.json"},
		{"requirement_source", "zeta.source", "docs/specs/a/requirements.v1.json"},
		{"test_inventory", "shared.identity", "proofkit/tests.json"},
	} {
		value := map[string]any{"kind": row.kind, "sourceRef": row.id, "path": row.path, "currentDigest": projectTestDigest(fixture.files[row.path])}
		if row.kind != "project_manifest" {
			value["expectedDigest"] = value["currentDigest"]
		}
		if row.kind == "requirement_source" {
			value["nodeId"], value["sourceRole"] = "project.root", "requirements"
		}
		physical = append(physical, value)
	}
	old, err := os.ReadFile("testdata/context-wire-v2/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]any{
		"schemaVersion": json.Number("3"), "contextKind": "proofkit.requirement-context", "catalogId": "shared.identity",
		"expectedDigestCoverage": "partial", "nonClaims": predecessorRecord(t, old)["nonClaims"],
		"projectOrigin": map[string]any{"manifest": fixture.original["manifest"], "testEvidenceInventory": fixture.original["testEvidenceInventory"]},
		"projections":   projections, "sources": physical,
	}
	resignProjectContext(t, result)
	return result
}

func resignProjectContext(t *testing.T, record map[string]any) {
	t.Helper()
	sources := []any{}
	for _, raw := range record["sources"].([]any) {
		value := deepClone(t, raw.(map[string]any))
		if _, ok := value["expectedDigest"]; !ok {
			value["expectedDigest"] = ""
		}
		sources = append(sources, value)
	}
	sort.Slice(sources, func(left, right int) bool {
		a, b := sources[left].(map[string]any), sources[right].(map[string]any)
		if a["kind"] != b["kind"] {
			return a["kind"].(string) < b["kind"].(string)
		}
		return a["sourceRef"].(string) < b["sourceRef"].(string)
	})
	record["snapshotId"] = projectTestDigest(projectTestJSON(t, map[string]any{
		"schemaVersion": json.Number("3"), "catalogId": record["catalogId"], "projectOrigin": record["projectOrigin"],
		"projections": record["projections"], "sources": sources,
	}))
}

func newProjectContextFixture(t *testing.T) projectContextFixture {
	t.Helper()
	fixture := projectfixture.New(t)
	inspection, err := projectstatus.InspectProject(context.Background(), fixture.Root)
	if err != nil || inspection.Project == nil {
		t.Fatalf("independent project capture: status=%s error=%v", inspection.Status.ProjectState, err)
	}
	return projectContextFixture{inspection: inspection, files: fixture.Files, original: fixture.Project}
}

func projectTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func projectTestDigest(content []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(content))
}
