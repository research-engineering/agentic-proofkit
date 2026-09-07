package requirementcontext

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// This independently authored ASCII fixture was captured and its explicit
// preimage checked at 3d6f81f6a85cb963f2bbb96073c75f1137afa153. Never regenerate
// expected.json from the candidate under test.
func TestContextPredecessorWireIdentity(t *testing.T) {
	const root = "testdata/context-wire-v2"
	const snapshotID = "sha256:6fb22780b923a77dd826e9eb3a2f55f59bec8bb526c684bc070e77ac60096467"
	expectedBytes, err := os.ReadFile(root + "/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(expectedBytes)); got != "42bf8527d17e2fb34a4e9a388d850f8265d2cf6390c27f46e94d90f658bfee15" {
		t.Fatal("independent predecessor packet bytes changed")
	}
	expected := predecessorRecord(t, expectedBytes)
	identities := []any{
		map[string]any{"currentDigest": "sha256:b5ed1da77cad818a8a2909b686d5c51d4b132812ab6c04c017bec13965dda3a3", "expectedDigest": "", "kind": "spec_tree", "path": "proofkit/tree.json", "sourceRef": "spec_tree:wire.tree"},
		map[string]any{"currentDigest": "sha256:5bcd8dfd746e8bbf85ae220e893eb7928f159a3577a1f31f82b849546d88b86b", "expectedDigest": "", "kind": "requirement_source", "nodeId": "wire.root", "path": "docs/specs/wire/requirements.v1.json", "sourceRef": "wire.requirements", "sourceRole": "requirements"},
	}
	preimage, err := json.MarshalIndent(map[string]any{"catalogId": "wire.catalog", "projections": expected["projections"], "sources": identities}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("sha256:%x", sha256.Sum256(append(preimage, '\n'))); got != snapshotID || expected["snapshotId"] != snapshotID {
		t.Fatal("independent predecessor preimage does not match its recorded identity")
	}
	catalogBytes, err := os.ReadFile(root + "/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	composed, err := Compose(root, predecessorRecord(t, catalogBytes))
	if err != nil || !reflect.DeepEqual(composed, expected) {
		t.Fatalf("Compose changed predecessor semantics: %v", err)
	}
	for _, version := range []string{"1", "2"} {
		t.Run("v"+version, func(t *testing.T) {
			input := predecessorRecord(t, expectedBytes)
			if version == "1" {
				input["schemaVersion"] = json.Number("1")
				delete(input, "expectedDigestCoverage")
				input["baselineVerification"] = "unverified"
				input["nonClaims"] = input["nonClaims"].([]any)[:2]
			}
			snapshot, err := AdmitSnapshot(input)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := stablejson.Marshal(SnapshotValue(snapshot))
			if err != nil || !bytes.Equal(encoded, expectedBytes) {
				t.Fatalf("admission changed predecessor wire: %v", err)
			}
			slice, err := SliceSnapshot(snapshot, map[string]any{"profile": "review", "requirementIds": []any{"REQ-WIRE-001"}}, "wire.slice")
			if err != nil {
				t.Fatal(err)
			}
			wantFragment := []any{map[string]any{
				"authority": "lookup_fragment_only", "omittedRequirementCount": 0,
				"projectionKind":           "proofkit.requirement-source-fragment",
				"requirements":             expected["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["requirements"],
				"selectedRequirementCount": 1, "sourceId": "wire.requirements", "totalRequirementCount": 1,
			}}
			if !reflect.DeepEqual(slice["projections"].(map[string]any)["requirementSources"], wantFragment) {
				t.Fatal("predecessor fragment fields or values changed")
			}
		})
	}
}

func predecessorRecord(t *testing.T, content []byte) map[string]any {
	t.Helper()
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}
