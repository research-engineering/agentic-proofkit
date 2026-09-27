package requirementcontext

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestSnapshotSizeBoundaryUsesCanonicalPrettyBytes(t *testing.T) {
	value, err := Compose(fixtureRepository(t), fixtureCatalog())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := AdmitSnapshot(value)
	if err != nil {
		t.Fatalf("boundary fixture failed admission before the size owner: %v", err)
	}
	pretty := independentSnapshotJSON(t, value, stablejson.LayoutPretty)
	compact := independentSnapshotJSON(t, value, stablejson.LayoutCompact)
	if len(compact) >= len(pretty)-1 {
		t.Fatal("fixture does not distinguish compact bytes from the pretty bound")
	}
	for _, test := range []struct {
		name  string
		limit int
		fail  bool
	}{
		{name: "below", limit: len(pretty) + 1},
		{name: "at", limit: len(pretty)},
		{name: "above", limit: len(pretty) - 1, fail: true},
		{name: "compact_only_fits", limit: len(compact), fail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := validateSnapshotSizeLimit(snapshot, test.limit)
			if test.fail {
				if err == nil || err.Error() != "requirement context snapshot exceeds byte limit" {
					t.Fatalf("size owner error = %v, want exact byte-limit rejection", err)
				}
				if !reflect.DeepEqual(got, Snapshot{}) {
					t.Fatal("size rejection retained a snapshot")
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, snapshot) {
				t.Fatalf("size owner changed an admitted snapshot: %v", err)
			}
			if !bytes.Equal(mustStableJSON(t, SnapshotValue(got)), pretty) {
				t.Fatal("size owner did not preserve canonical pretty bytes")
			}
		})
	}
	if !bytes.Equal(mustStableJSON(t, SnapshotValue(snapshot)), pretty) {
		t.Fatal("size validation mutated its input")
	}
	invalid := snapshot
	invalid.Projections = deepClone(t, snapshot.Projections)
	invalid.Projections["unknown"] = true
	if got, err := validateSnapshotSizeLimit(invalid, 1); err == nil || err.Error() == "requirement context snapshot exceeds byte limit" || !reflect.DeepEqual(got, Snapshot{}) {
		t.Fatalf("generated shape must still reject before size: %v", err)
	}
}

// The semantic boundary tests use a small admitted fixture. This separate guard
// binds that exact implementation to the production constant, without repeating
// full 8 MiB child admission and encoding for every boundary case.
func TestSnapshotSizeProductionLimitBinding(t *testing.T) {
	if maxSnapshotBytes != 8<<20 {
		t.Fatal("production pretty snapshot limit changed")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "model.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			functions[function.Name.Name] = function
		}
	}
	for _, test := range []struct {
		name   string
		callee string
		args   []string
	}{
		{name: "admitCatalogSnapshot", callee: "validateSnapshotSize", args: []string{"snapshot"}},
		{name: "validateSnapshotSize", callee: "validateSnapshotSizeLimit", args: []string{"snapshot", "maxSnapshotBytes"}},
	} {
		function := functions[test.name]
		if function == nil || function.Body == nil || len(function.Body.List) == 0 {
			t.Fatalf("production size binding %s is missing", test.name)
		}
		if test.name == "validateSnapshotSize" && len(function.Body.List) != 1 {
			t.Fatal("production size owner must directly delegate to the tested helper")
		}
		statement, ok := function.Body.List[len(function.Body.List)-1].(*ast.ReturnStmt)
		if !ok || len(statement.Results) != 1 {
			t.Fatalf("%s must return its size owner's result", test.name)
		}
		call, ok := statement.Results[0].(*ast.CallExpr)
		if !ok || len(call.Args) != len(test.args) {
			t.Fatalf("%s lost its size binding", test.name)
		}
		callee, ok := call.Fun.(*ast.Ident)
		if !ok || callee.Name != test.callee {
			t.Fatalf("%s bypassed its size owner", test.name)
		}
		for index, expression := range call.Args {
			identifier, ok := expression.(*ast.Ident)
			if !ok || identifier.Name != test.args[index] {
				t.Fatalf("%s changed its snapshot or limit binding", test.name)
			}
		}
	}
}

func TestComposePreservesIdentityLayoutsAndDetachedAdmission(t *testing.T) {
	root := fixtureRepository(t)
	for _, mode := range []string{"none", "partial", "all"} {
		t.Run(mode, func(t *testing.T) {
			catalog := fixtureCatalog()
			if mode != "none" {
				setExpectedFixtureDigest(t, root, catalog["specTree"].(map[string]any))
			}
			if mode == "all" {
				setExpectedFixtureDigest(t, root, catalog["requirementSources"].([]any)[0].(map[string]any))
			}
			value, err := Compose(root, catalog)
			if err != nil || value["expectedDigestCoverage"] != mode {
				t.Fatalf("Compose digest coverage %s: %v", mode, err)
			}
			identities := []any{}
			for _, raw := range value["sources"].([]any) {
				source := raw.(map[string]any)
				identity := map[string]any{"currentDigest": source["currentDigest"], "expectedDigest": "", "kind": source["kind"], "path": source["path"], "sourceRef": source["sourceRef"]}
				for _, key := range []string{"expectedDigest", "nodeId", "sourceRole"} {
					if v, present := source[key]; present {
						identity[key] = v
					}
				}
				identities = append(identities, identity)
			}
			preimage := independentSnapshotJSON(t, map[string]any{"catalogId": catalog["catalogId"], "projections": value["projections"], "sources": identities}, stablejson.LayoutPretty)
			if want := fmt.Sprintf("sha256:%x", sha256.Sum256(preimage)); value["snapshotId"] != want {
				t.Fatal("Compose identity differs from the independent preimage")
			}
			admitted, err := AdmitSnapshot(value)
			if err != nil {
				t.Fatal(err)
			}
			before := map[stablejson.Layout][]byte{}
			for _, layout := range []stablejson.Layout{stablejson.LayoutPretty, stablejson.LayoutCompact} {
				before[layout] = independentSnapshotJSON(t, value, layout)
				got, err := stablejson.MarshalLayout(SnapshotValue(admitted), layout)
				if err != nil || !bytes.Equal(got, before[layout]) {
					t.Fatalf("re-admission changed %s bytes: %v", layout, err)
				}
			}
			value["sources"].([]any)[0].(map[string]any)["path"] = "changed.json"
			source := value["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)
			source["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)["statementCompletion"] = "Changed caller statement."
			value["nonClaims"].([]any)[0] = "Changed caller boundary."
			for layout, want := range before {
				got, err := stablejson.MarshalLayout(SnapshotValue(admitted), layout)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("caller mutation changed admitted %s bytes: %v", layout, err)
				}
			}
		})
	}
}

func independentSnapshotJSON(t *testing.T, value any, layout stablejson.Layout) []byte {
	t.Helper()
	var result bytes.Buffer
	encoder := json.NewEncoder(&result)
	encoder.SetEscapeHTML(false)
	if layout == stablejson.LayoutPretty {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}
