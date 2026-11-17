package receiptproduceradmission

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func TestProducerPathRolesPreserveExactReferences(t *testing.T) {
	for _, sample := range []struct{ name, ref string }{
		{"ordinary", "artifacts/result.json"}, {"task", "inputs/task-requirements.json"},
		{"risk", "docs/risk-assessment.md"}, {"legacy", "artifacts/run-sk-abcdefghij.log"},
		{"leading_space", " artifacts/result.json"}, {"trailing_space", "artifacts/result.json "},
		{"long", strings.Repeat("segment/", 70) + "task-requirements.json"},
	} {
		ref := sample.ref
		for _, role := range []string{"producer_evidence", "receipt_evidence", "provenance", "artifacts"} {
			t.Run(role+"/"+sample.name, func(t *testing.T) {
				input := validAdmission()
				producer := input["producers"].([]any)[0].(map[string]any)
				receipt := input["receipts"].([]any)[0].(map[string]any)
				switch role {
				case "producer_evidence":
					producer["evidenceRefs"] = []any{ref}
				case "receipt_evidence":
					receipt["evidenceRef"] = ref
				case "provenance":
					receipt["provenanceRef"] = ref
				case "artifacts":
					receipt["artifactRefs"] = []any{ref}
				}
				value, err := admitInput(input)
				if err != nil {
					t.Fatalf("canonical %s path refused: %v", role, err)
				}
				var got string
				switch role {
				case "producer_evidence":
					got = value.Producers[0].EvidenceRefs[0]
				case "receipt_evidence":
					got = value.Receipts[0].EvidenceRef
				case "provenance":
					got = *value.Receipts[0].ProvenanceRef
				case "artifacts":
					got = value.Receipts[0].ArtifactRefs[0]
				}
				if got != ref {
					t.Fatalf("structural identity changed: got=%q want=%q", got, ref)
				}
				_, record, code, err := Evaluate(input)
				if err != nil || code != 0 || record.State != "passed" {
					t.Fatalf("unchanged producer policy failed: code=%d state=%s err=%v", code, record.State, err)
				}
			})
		}
	}
}

func TestProducerPathAdmissionKeepsTypeOrderAndNullPolicy(t *testing.T) {
	for _, raw := range []any{nil, false, 7, []any{}, map[string]any{}, ""} {
		if _, err := pathField(raw, "path"); err == nil {
			t.Fatalf("scalar path accepted invalid value of type %T", raw)
		}
	}
	for _, raw := range []any{nil, "a.json", []any{false}, []any{nil}, []any{"b.json", "a.json"}, []any{"a.json", "a.json"}} {
		if _, err := sortedPaths(raw, "paths", true); err == nil {
			t.Fatalf("input-sorted path list accepted invalid %T input", raw)
		}
	}
	if _, err := sortedPaths([]any{}, "paths", false); err == nil {
		t.Fatal("required path list accepted empty input")
	}
	if value, err := sortedPaths([]any{}, "paths", true); err != nil || len(value) != 0 {
		t.Fatal("optional path list refused empty input")
	}
	for _, role := range []string{"producer_evidence", "artifacts"} {
		for _, raw := range []any{nil, []any{}} {
			input := validAdmission()
			if role == "producer_evidence" {
				input["producers"].([]any)[0].(map[string]any)["evidenceRefs"] = raw
			} else {
				input["receipts"].([]any)[0].(map[string]any)["artifactRefs"] = raw
			}
			_, _, err := Build(input)
			if (err != nil) != (raw == nil) {
				t.Fatalf("%s absence/null versus empty-list policy changed: %v", role, err)
			}
		}
	}
	want := []string{" a.json", "a.json", "a.json "}
	if got, err := sortedPaths([]any{want[0], want[1], want[2]}, "paths", false); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("distinct significant whitespace paths collapsed: got=%q err=%v", got, err)
	}
	for _, absent := range []bool{false, true} {
		input := validAdmission()
		receipt := input["receipts"].([]any)[0].(map[string]any)
		receipt["satisfiesMergeObligation"] = false
		if absent {
			delete(receipt, "provenanceRef")
		} else {
			receipt["provenanceRef"] = nil
		}
		value, record, code, err := Evaluate(input)
		if err != nil || code != 0 || record.State != "passed" || value.Receipts[0].ProvenanceRef != nil {
			t.Fatalf("optional provenance absence/null changed: code=%d err=%v", code, err)
		}
	}
}

func TestProducerPathAdmissionRetainsProtectedRefusalsAndProse(t *testing.T) {
	fixtures := admit.ReportVisibleRedactionFixtures()
	if len(fixtures) == 0 {
		t.Fatal("protected signature catalog is empty")
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			if _, err := pathField("inputs/prefix"+fixture.Input+"suffix.json", "path"); err == nil {
				t.Fatalf("protected signature class %s admitted", fixture.Name)
			}
		})
	}
	for _, ref := range []string{".", "/absolute", "../outside", "a/../outside", "a//b", "https://example.test/a", "C:/outside", "a\\b", "a\x00b", "a\nb", "a\tb", "a\rb", "a\x7fb"} {
		if _, err := pathField(ref, "path"); err == nil {
			t.Fatalf("unsafe path admitted: %q", ref)
		}
	}
	for _, role := range []string{"owner", "nonClaims"} {
		input := validAdmission()
		if role == "owner" {
			input["producers"].([]any)[0].(map[string]any)["owner"] = "docs/risk-assessment.md"
		} else {
			input["nonClaims"] = []any{"inputs/task-requirements.json"}
		}
		if _, _, err := Build(input); err == nil {
			t.Fatalf("path repair weakened prose field %s", role)
		}
	}
}
