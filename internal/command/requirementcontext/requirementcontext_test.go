package requirementcontext

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestComposeAndSliceRoundTrip(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.039174333591545173112362713528481218186528989446819372039588644025024411317142")
	root := fixtureRepository(t)
	contextValue, err := Compose(root, fixtureCatalog())
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}
	snapshot, err := AdmitSnapshot(contextValue)
	if err != nil {
		t.Fatalf("AdmitSnapshot() error = %v", err)
	}
	if snapshot.ExpectedDigestCoverage != "none" {
		t.Fatalf("expected digest coverage = %q, want none", snapshot.ExpectedDigestCoverage)
	}
	output, err := Slice(map[string]any{
		"schemaVersion": json.Number("1"),
		"sliceId":       "consumer.context.slice",
		"context":       contextValue,
		"query": map[string]any{
			"profile": "specification",
			"nodeIds": []any{"spec.root"},
		},
	})
	if err != nil {
		t.Fatalf("Slice() error = %v", err)
	}
	direct, err := SliceSnapshot(snapshot, map[string]any{
		"profile": "specification",
		"nodeIds": []any{"spec.root"},
	}, "consumer.context.slice")
	if err != nil {
		t.Fatalf("SliceSnapshot() error = %v", err)
	}
	if !sameStableJSON(t, output, direct) {
		t.Fatal("SliceSnapshot() drifted from public Slice() projection")
	}
	if output["state"] != "selected" || output["snapshotId"] != snapshot.SnapshotID {
		t.Fatalf("unexpected slice output: %#v", output)
	}
	projections := output["projections"].(map[string]any)
	sources := projections["requirementSources"].([]any)
	if len(sources) != 1 {
		t.Fatalf("selected source count = %d, want 1", len(sources))
	}
	requirements := sources[0].(map[string]any)["requirements"].([]any)
	if len(requirements) == 0 {
		t.Fatal("slice omitted all requirements from explicitly selected source")
	}
}

func sameStableJSON(t *testing.T, left, right any) bool {
	t.Helper()
	leftJSON, err := stablejson.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	rightJSON, err := stablejson.Marshal(right)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(leftJSON, rightJSON)
}

func TestV1DigestCoverageAdapters(t *testing.T) {
	root := fixtureRepository(t)
	for _, test := range []struct {
		name     string
		covered  []string
		expected string
		legacy   string
	}{
		{name: "none", expected: "none", legacy: "unverified"},
		{name: "partial", covered: []string{"specTree"}, expected: "partial", legacy: "partially_verified"},
		{name: "all", covered: []string{"specTree", "requirementSources"}, expected: "all", legacy: "verified"},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog := fixtureCatalog()
			for _, owner := range test.covered {
				switch owner {
				case "specTree":
					setExpectedFixtureDigest(t, root, catalog["specTree"].(map[string]any))
				case "requirementSources":
					setExpectedFixtureDigest(t, root, catalog["requirementSources"].([]any)[0].(map[string]any))
				}
			}
			v2, err := Compose(root, catalog)
			if err != nil {
				t.Fatal(err)
			}
			if v2["schemaVersion"] != json.Number("2") || v2["expectedDigestCoverage"] != test.expected {
				t.Fatalf("v2 projection = %#v, want coverage %q", v2, test.expected)
			}
			v1 := v1SnapshotFixture(t, v2, test.legacy)
			admitted, err := AdmitSnapshot(v1)
			if err != nil {
				t.Fatalf("AdmitSnapshot(v1) error = %v", err)
			}
			if got, want := mustStableJSON(t, SnapshotValue(admitted)), mustStableJSON(t, v2); !bytes.Equal(got, want) {
				t.Fatalf("v1 normalized output differs from v2\n got: %s\nwant: %s", got, want)
			}
		})
	}

	v2, err := Compose(root, fixtureCatalog())
	if err != nil {
		t.Fatal(err)
	}
	mixedV2 := deepClone(t, v2)
	mixedV2["baselineVerification"] = "unverified"
	if _, err := AdmitSnapshot(mixedV2); err == nil {
		t.Fatal("AdmitSnapshot accepted mixed v1/v2 fields under schema v2")
	}
	mixedV1 := v1SnapshotFixture(t, v2, "unverified")
	mixedV1["expectedDigestCoverage"] = "none"
	if _, err := AdmitSnapshot(mixedV1); err == nil {
		t.Fatal("AdmitSnapshot accepted mixed v1/v2 fields under schema v1")
	}
	malformedV1 := v1SnapshotFixture(t, v2, "verified")
	if _, err := AdmitSnapshot(malformedV1); err == nil {
		t.Fatal("AdmitSnapshot accepted a malformed legacy coverage claim")
	}
}

func setExpectedFixtureDigest(t *testing.T, root string, entry map[string]any) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(entry["path"].(string))))
	if err != nil {
		t.Fatal(err)
	}
	entry["expectedSourceDigest"] = digest.SHA256TextRef(string(content))
}

func v1SnapshotFixture(t *testing.T, v2 map[string]any, legacy string) map[string]any {
	t.Helper()
	v1 := deepClone(t, v2)
	delete(v1, "expectedDigestCoverage")
	v1["baselineVerification"] = legacy
	v1["nonClaims"] = admit.StringSliceToAny(v1BoundaryNonClaims)
	v1["schemaVersion"] = json.Number("1")
	return v1
}

func mustStableJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestSnapshotAdmissionRejectsForgedCoverageAndProjectionLedger(t *testing.T) {
	contextValue, err := Compose(fixtureRepository(t), fixtureCatalog())
	if err != nil {
		t.Fatal(err)
	}
	forged := deepClone(t, contextValue)
	forgedSources := forged["sources"].([]any)
	for _, raw := range forgedSources {
		source := raw.(map[string]any)
		source["expectedDigest"] = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	}
	forged["expectedDigestCoverage"] = "all"
	resignSnapshot(t, forged)
	if _, err := AdmitSnapshot(forged); err == nil {
		t.Fatal("AdmitSnapshot accepted mismatched expected digests as fully covered")
	}

	phantom := deepClone(t, contextValue)
	phantom["sources"] = append(phantom["sources"].([]any), map[string]any{"currentDigest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "kind": "coverage", "path": "artifacts/coverage.json", "sourceRef": "coverage:phantom.coverage"})
	resignSnapshot(t, phantom)
	if _, err := AdmitSnapshot(phantom); err == nil {
		t.Fatal("AdmitSnapshot accepted a source record without its owner projection")
	}

	oversized := deepClone(t, contextValue)
	requirement := oversized["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)[0].(map[string]any)
	requirement["invariant"] = strings.Repeat("a", maxSnapshotBytes)
	resignSnapshot(t, oversized)
	if _, err := AdmitSnapshot(oversized); err == nil {
		t.Fatal("AdmitSnapshot accepted a snapshot larger than the producer bound")
	}
}

func TestSliceUsesExplicitLookupFragments(t *testing.T) {
	contextValue, err := Compose(fixtureRepository(t), fixtureCatalog())
	if err != nil {
		t.Fatal(err)
	}
	output, err := Slice(map[string]any{"context": contextValue, "query": map[string]any{"maxRequirements": json.Number("1"), "profile": "specification", "requirementIds": []any{"REQ-PROOFKIT-SPEC-001"}}, "schemaVersion": json.Number("1"), "sliceId": "consumer.fragment"})
	if err != nil {
		t.Fatal(err)
	}
	projections := output["projections"].(map[string]any)
	source := projections["requirementSources"].([]any)[0].(map[string]any)
	if source["projectionKind"] != "proofkit.requirement-source-fragment" || source["authority"] != "lookup_fragment_only" || source["selectedRequirementCount"] != 1 {
		t.Fatalf("unexpected source fragment: %#v", source)
	}
	tree := projections["specTree"].(map[string]any)
	if tree["projectionKind"] != "proofkit.requirement-spec-tree-fragment" || tree["authority"] != "lookup_fragment_only" {
		t.Fatalf("unexpected tree fragment: %#v", tree)
	}
}

func TestSlicePreservesTransitiveLifecycleReplacementClosure(t *testing.T) {
	root := fixtureRepository(t)
	path := filepath.Join(root, "docs/specs/proofkit-spec-proof-core/requirements.v1.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	source := decoded.(map[string]any)
	requirements := source["requirements"].([]any)
	first := requirements[0].(map[string]any)
	second := requirements[1].(map[string]any)
	firstID := first["requirementId"].(string)
	secondID := second["requirementId"].(string)
	first["claimLevel"] = "advisory"
	first["lifecycle"] = map[string]any{"evidenceRefs": []any{"proof.lifecycle.first"}, "replacementRequirementIds": []any{secondID}, "state": "superseded"}
	second["lifecycle"] = map[string]any{"evidenceRefs": []any{}, "replacementRequirementIds": []any{}, "state": "active"}
	updated, err := stablejson.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, updated, 0o644); err != nil {
		t.Fatal(err)
	}
	contextValue, err := Compose(root, fixtureCatalog())
	if err != nil {
		t.Fatal(err)
	}
	output, err := Slice(map[string]any{"context": contextValue, "query": map[string]any{"maxRequirements": json.Number("2"), "profile": "review", "requirementIds": []any{firstID}}, "schemaVersion": json.Number("1"), "sliceId": "consumer.lifecycle-closure"})
	if err != nil {
		t.Fatal(err)
	}
	selected := output["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)
	got := make([]string, 0, len(selected))
	for _, raw := range selected {
		got = append(got, raw.(map[string]any)["requirementId"].(string))
	}
	if !containsAll(got, firstID, secondID) {
		t.Fatalf("selected lifecycle closure=%v", got)
	}
	if _, err := Slice(map[string]any{"context": contextValue, "query": map[string]any{"maxRequirements": json.Number("1"), "profile": "review", "requirementIds": []any{firstID}}, "schemaVersion": json.Number("1"), "sliceId": "consumer.lifecycle-closure-bounded"}); err == nil {
		t.Fatal("Slice accepted a bound that cannot retain mandatory lifecycle closure")
	}
}

func containsAll(values []string, expected ...string) bool {
	set := map[string]struct{}{}
	for _, value := range values {
		set[value] = struct{}{}
	}
	for _, value := range expected {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	return true
}

func deepClone(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	return decoded.(map[string]any)
}

func resignSnapshot(t *testing.T, value map[string]any) {
	t.Helper()
	sources := value["sources"].([]any)
	identitySources := make([]any, 0, len(sources))
	for _, raw := range sources {
		source := raw.(map[string]any)
		identity := map[string]any{"currentDigest": source["currentDigest"], "expectedDigest": "", "kind": source["kind"], "path": source["path"], "sourceRef": source["sourceRef"]}
		for _, key := range []string{"expectedDigest", "nodeId", "sourceRole"} {
			if source[key] != nil {
				identity[key] = source[key]
			}
		}
		identitySources = append(identitySources, identity)
	}
	encoded, err := stablejson.Marshal(map[string]any{"catalogId": value["catalogId"], "projections": value["projections"], "sources": identitySources})
	if err != nil {
		t.Fatal(err)
	}
	value["snapshotId"] = digest.SHA256TextRef(string(encoded))
}

func TestSliceRejectsTamperedSnapshotAndUnknownNode(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.085802294599012556735496328767610257842830634122573088743085183818381349380300")
	root := fixtureRepository(t)
	contextValue, err := Compose(root, fixtureCatalog())
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}
	tampered := cloneMap(contextValue)
	tampered["catalogId"] = "consumer.other.catalog"
	if _, err := AdmitSnapshot(tampered); err == nil {
		t.Fatal("AdmitSnapshot accepted content with a stale snapshotId")
	}
	_, err = Slice(map[string]any{
		"schemaVersion": json.Number("1"),
		"sliceId":       "consumer.context.slice",
		"context":       contextValue,
		"query": map[string]any{
			"profile": "specification",
			"nodeIds": []any{"spec.unknown"},
		},
	})
	if err == nil {
		t.Fatal("Slice accepted an unknown explicit node")
	}
	_, err = Slice(map[string]any{
		"schemaVersion": json.Number("1"), "sliceId": "consumer.context.slice", "context": contextValue,
		"query": map[string]any{"profile": "specification", "requirementIds": []any{"REQ-UNKNOWN-001"}},
	})
	if err == nil {
		t.Fatal("Slice accepted an unknown explicit requirement")
	}
	bounded, err := Slice(map[string]any{
		"schemaVersion": json.Number("1"), "sliceId": "consumer.context.slice", "context": contextValue,
		"query": map[string]any{"profile": "specification", "nodeIds": []any{"spec.root"}, "maxNodes": json.Number("1")},
	})
	if err != nil {
		t.Fatalf("bounded Slice() error = %v", err)
	}
	omissions := bounded["omissions"].([]any)
	if len(omissions) != 1 || omissions[0].(map[string]any)["count"] != 1 {
		t.Fatalf("bounded omissions = %#v, want one omitted node", omissions)
	}
}

func TestComposeRejectsRepositoryBoundaryAndFreshnessViolations(t *testing.T) {
	t.Run("parent escape", func(t *testing.T) {
		catalog := fixtureCatalog()
		catalog["specTree"].(map[string]any)["path"] = "../outside.json"
		if _, err := Compose(fixtureRepository(t), catalog); err == nil {
			t.Fatal("Compose accepted parent-directory escape")
		}
	})
	t.Run("symlink source", func(t *testing.T) {
		root := fixtureRepository(t)
		path := filepath.Join(root, "proofkit/spec-tree.json")
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, "proofkit/real-tree.json")
		if err := os.WriteFile(target, content, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real-tree.json", path); err != nil {
			t.Fatal(err)
		}
		if _, err := Compose(root, fixtureCatalog()); err == nil {
			t.Fatal("Compose accepted symlink source")
		}
	})
	t.Run("oversized source", func(t *testing.T) {
		root := fixtureRepository(t)
		if err := os.WriteFile(filepath.Join(root, "proofkit/spec-tree.json"), bytes.Repeat([]byte(" "), maxSourceBytes+1), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Compose(root, fixtureCatalog()); err == nil {
			t.Fatal("Compose accepted oversized source")
		}
	})
	t.Run("expected digest mismatch", func(t *testing.T) {
		catalog := fixtureCatalog()
		catalog["specTree"].(map[string]any)["expectedSourceDigest"] = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		if _, err := Compose(fixtureRepository(t), catalog); err == nil {
			t.Fatal("Compose accepted mismatched expected source digest")
		}
	})
}

func fixtureRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	repoRoot := filepath.Clean(filepath.Join("..", "..", ".."))
	source, err := os.ReadFile(filepath.Join(repoRoot, "docs/specs/proofkit-spec-proof-core/requirements.v1.json"))
	if err != nil {
		t.Fatalf("read requirement source fixture: %v", err)
	}
	writeFixture(t, root, "docs/specs/proofkit-spec-proof-core/requirements.v1.json", source)
	tree := map[string]any{
		"schemaVersion":     json.Number("2"),
		"treeId":            "proofkit.spec-tree",
		"rootNodeId":        "spec.root",
		"callerAnnotations": []any{},
		"edges":             []any{map[string]any{"parentNodeId": "spec.root", "childNodeId": "spec.child"}},
		"overlays":          []any{},
		"nodes": []any{map[string]any{
			"nodeId":            "spec.root",
			"nodeKind":          "meta_spec",
			"label":             "Specification root",
			"displayOrder":      json.Number("1"),
			"callerAnnotations": []any{},
			"sourceRefs": []any{map[string]any{
				"sourceRefId":   "spec.root.requirements",
				"sourceRefKind": "source_id",
				"sourceRole":    "requirements",
				"sourceId":      "proofkit.spec-proof-core.requirements",
			}},
		}, map[string]any{
			"nodeId": "spec.child", "nodeKind": "module_spec", "label": "Child specification", "displayOrder": json.Number("2"), "callerAnnotations": []any{},
			"sourceRefs": []any{map[string]any{"sourceRefId": "spec.child.requirements", "sourceRefKind": "source_id", "sourceRole": "requirements", "sourceId": "proofkit.spec-proof-core.requirements"}},
		}},
	}
	encoded, err := stablejson.Marshal(tree)
	if err != nil {
		t.Fatalf("marshal tree fixture: %v", err)
	}
	writeFixture(t, root, "proofkit/spec-tree.json", encoded)
	return root
}

func fixtureCatalog() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"catalogId":     "consumer.spec-context",
		"specTree": map[string]any{
			"path": "proofkit/spec-tree.json",
		},
		"requirementSources": []any{map[string]any{
			"nodeId": "spec.root",
			"path":   "docs/specs/proofkit-spec-proof-core/requirements.v1.json",
		}},
	}
}

func cloneMap(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func writeFixture(t *testing.T, root, path string, content []byte) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("create fixture parent: %v", err)
	}
	if err := os.WriteFile(target, content, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
