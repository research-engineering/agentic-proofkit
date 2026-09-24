package requirementcoverageview

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestGroupedCoveragePreservesConditionalMeaningAcrossOutputs(t *testing.T) {
	input := validCoverageInput(t).(map[string]any)
	source := input["requirementSource"].(map[string]any)
	premise := "Only the <authenticated> caller enters this operation."
	coverageSourceGroup(source)["sharedPremises"] = []any{premise}
	source["nonClaimDefinitions"] = []any{map[string]any{"nonClaimId": "NCL-COVERAGE", "statement": "This scenario does not prove freshness."}}
	fields := sourceRequirement(input)
	fields["nonClaimRefs"] = []any{"NCL-COVERAGE"}
	fields["externalNonClaimRefs"] = []any{"consumer.external-boundary"}
	value, exit, err := BuildJSON(input, Options{})
	if err != nil || exit != 0 {
		t.Fatalf("BuildJSON(): %v, exit %d", err, exit)
	}
	view := value.(map[string]any)
	if !reflect.DeepEqual(view["nonClaimDefinitions"], source["nonClaimDefinitions"]) {
		t.Fatal("coverage local reference has no definition")
	}
	if view["schemaVersion"] != 4 {
		t.Fatalf("unversioned source delta: %v", view["schemaVersion"])
	}
	row := view["requirementCoverage"].([]any)[0].(map[string]any)
	for key, want := range map[string][]any{
		"sharedPremises": {premise}, "nonClaimRefs": {"NCL-COVERAGE"}, "externalNonClaimRefs": {"consumer.external-boundary"},
		"nonClaims": {"Coverage fixture does not execute tests."},
	} {
		if !reflect.DeepEqual(row[key], want) {
			t.Fatalf("%s = %v; want %v", key, row[key], want)
		}
	}
	encoded, err := stablejson.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := AdmitOutput(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(admitted["requirementCoverage"], wire.(map[string]any)["requirementCoverage"]) {
		t.Fatal("output admission lost source conditions or reference roles")
	}
	for _, field := range []string{"sharedPremises", "nonClaimRefs", "externalNonClaimRefs"} {
		for _, replacement := range []any{nil, "not an array", []any{"z", "a"}} {
			mutated := cloneCoverageJSONValue(wire).(map[string]any)
			mutatedRow := mutated["requirementCoverage"].([]any)[0].(map[string]any)
			if replacement == nil {
				delete(mutatedRow, field)
			} else {
				mutatedRow[field] = replacement
			}
			if _, err := AdmitOutput(mutated); err == nil {
				t.Fatalf("accepted absent or malformed %s = %#v", field, replacement)
			}
		}
	}
	markdown, _, err := BuildMarkdown(input)
	if err != nil || !strings.Contains(markdown, "Shared premise: Only the &lt;authenticated&gt; caller enters this operation\\.") {
		t.Fatalf("Markdown lost or failed to escape condition: %v\n%s", err, markdown)
	}
	document, _, err := BuildHTML(input)
	if err != nil || !strings.Contains(document, "<li>Only the &lt;authenticated&gt; caller enters this operation.</li>") {
		t.Fatalf("HTML lost or failed to escape visible condition: %v", err)
	}
	fragment := SelectRequirements(admitted, map[string]struct{}{"REQ-PROOFKIT-COVERAGE-001": {}})
	if fragment["schemaVersion"] != json.Number("2") || !reflect.DeepEqual(fragment["requirementCoverage"], admitted["requirementCoverage"]) {
		t.Fatal("lookup fragment lost conditional meaning or its versioned identity")
	}
	for _, key := range []string{"sourceId", "nonClaimDefinitions", "nonClaims"} {
		if !reflect.DeepEqual(fragment[key], admitted[key]) {
			t.Fatalf("selected fragment lost %s", key)
		}
	}
	empty := SelectRequirements(admitted, map[string]struct{}{})
	if len(empty["nonClaimDefinitions"].([]any)) != 0 || !reflect.DeepEqual(empty["nonClaims"], admitted["nonClaims"]) {
		t.Fatal("empty selection retained unused support or erased report boundaries")
	}
	fragment["nonClaimDefinitions"].([]any)[0].(map[string]any)["statement"] = "Changed detached definition."
	fragment["nonClaims"].([]any)[0] = "Changed detached boundary."
	if !reflect.DeepEqual(admitted["nonClaimDefinitions"], source["nonClaimDefinitions"]) || reflect.DeepEqual(fragment["nonClaims"], admitted["nonClaims"]) {
		t.Fatal("fragment aliases the admitted report")
	}
	for name, mutate := range map[string]func(map[string]any){
		"missing dictionary": func(value map[string]any) { delete(value, "nonClaimDefinitions") },
		"dangling":           func(value map[string]any) { value["nonClaimDefinitions"] = []any{} },
		"unused": func(value map[string]any) {
			value["nonClaimDefinitions"] = append(value["nonClaimDefinitions"].([]any), map[string]any{"nonClaimId": "NCL-UNUSED", "statement": "Unused restriction."})
		},
		"noncanonical namespace": func(value map[string]any) { value["sourceId"] = " " + value["sourceId"].(string) },
		"direct named overlap": func(value map[string]any) {
			value["requirementCoverage"].([]any)[0].(map[string]any)["nonClaims"] = []any{"This scenario does not prove freshness."}
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneCoverageJSONValue(wire).(map[string]any)
			mutate(mutated)
			if _, err := AdmitOutput(mutated); err == nil {
				t.Fatal("inconsistent definition support admitted")
			}
		})
	}
	for _, rendered := range []string{markdown, document} {
		if !strings.Contains(rendered, "This scenario does not prove freshness") {
			t.Fatal("human coverage output omitted the named restriction")
		}
	}
}

func TestGroupedCoverageRejectsOldInputIdentity(t *testing.T) {
	input := validCoverageInput(t).(map[string]any)
	input["schemaVersion"] = json.Number("2")
	value, exit, err := BuildJSON(input, Options{})
	if err == nil || exit != 1 || value != nil || !strings.Contains(err.Error(), "schemaVersion must be 3") {
		t.Fatalf("old identity accepted: %v, %d, %v", value, exit, err)
	}
}
