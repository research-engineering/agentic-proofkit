package branchauthority

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestBranchStructuresDeclareExactNestedCarriers(t *testing.T) {
	input, output := InputStructure(), OutputStructure()
	for _, test := range []struct {
		schema map[string]any
		path   string
		want   any
	}{
		{input, "/required", []any{"branchRefs", "nonClaims", "preexistingFailures", "reportId", "schemaVersion"}},
		{input, "/additionalProperties", false},
		{input, "/properties/schemaVersion/const", json.Number("1")},
		{input, "/properties/schemaVersion/x-proofkit-number-encoding", "canonical-int64"},
		{input, "/properties/reportId/maxLength", 256},
		{input, "/properties/branchRefs/minItems", 1},
		{input, "/properties/branchRefs/items/additionalProperties", false},
		{input, "/properties/branchRefs/items/required", []any{"evidenceRef", "expectedBranch", "nonClaims", "observedBranch", "refId", "refKind", "required"}},
		{input, "/properties/branchRefs/items/properties/required/type", "boolean"},
		{input, "/properties/branchRefs/items/properties/refId/maxLength", 256},
		{input, "/properties/branchRefs/items/properties/refKind/enum", []any{"branch_protection", "ci_push", "consumer_fixture", "manual_workflow_guard", "package_source", "publish_guard", "release_source", "repository_default", "review_base"}},
		{input, "/properties/branchRefs/items/properties/nonClaims/minItems", 1},
		{input, "/properties/preexistingFailures/type", "array"},
		{input, "/properties/preexistingFailures/uniqueItems", true},
		{input, "/properties/nonClaims/minItems", 1},
		{output, "/required", []any{"diagnostics", "nonClaims", "reportId", "reportKind", "ruleResults", "schemaVersion", "state", "summary"}},
		{output, "/properties/reportKind/enum", []any{"proofkit.branch-authority"}},
		{output, "/properties/state/enum", []any{"failed", "passed"}},
		{output, "/properties/reportId/maxLength", 256},
		{output, "/properties/summary/required", []any{"advisoryDriftCount", "branchRefCount", "requiredDriftCount"}},
		{output, "/properties/summary/properties/branchRefCount/minimum", json.Number("1")},
		{output, "/properties/diagnostics/minItems", 3},
		{output, "/properties/diagnostics/maxItems", 3},
		{output, "/properties/diagnostics/items", false},
		{output, "/properties/diagnostics/prefixItems/0/properties/key/const", "advisoryDriftRefIds"},
		{output, "/properties/diagnostics/prefixItems/1/properties/key/const", "branchRefs"},
		{output, "/properties/diagnostics/prefixItems/2/properties/key/const", "requiredDriftRefIds"},
		{output, "/properties/diagnostics/prefixItems/1/properties/value/items/required", []any{"alignment", "evidenceRef", "expectedBranch", "nonClaims", "observedBranch", "refId", "refKind", "required"}},
		{output, "/properties/ruleResults/minItems", 3},
		{output, "/properties/ruleResults/maxItems", 3},
		{output, "/properties/nonClaims/minItems", 6},
		{output, "/properties/nonClaims/uniqueItems", true},
	} {
		if got := branchSchemaValue(t, test.schema, test.path); !reflect.DeepEqual(got, test.want) {
			t.Fatalf("%s=%#v, want %#v", test.path, got, test.want)
		}
	}
	for _, schema := range []map[string]any{input, output} {
		if _, err := stablejson.Marshal(schema); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBranchStructuresAreDetachedFromEachOtherAndNativePolicy(t *testing.T) {
	first := InputStructure()
	want, err := stablejson.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	branchSchemaValue(t, first, "/properties/nonClaims/items/not/enum").([]any)[0] = "mutated"
	branchSchemaValue(t, first, "/properties/branchRefs/items/properties/refKind/enum").([]any)[0] = "mutated"
	branchSchemaValue(t, first, "/properties/reportId").(map[string]any)["maxLength"] = 1
	if branchSchemaValue(t, first, "/properties/branchRefs/items/properties/refId/maxLength") != 256 {
		t.Fatal("separate identifier projections share mutable state")
	}
	got, err := stablejson.Marshal(InputStructure())
	if err != nil || string(got) != string(want) {
		t.Fatalf("caller changed future projection: %v", err)
	}
	record, code, err := Build(validBranchAuthorityInput("main"))
	if err != nil || code != 0 || len(record.NonClaims) != 6 {
		t.Fatalf("caller changed native policy: code=%d error=%v", code, err)
	}
	for _, value := range record.NonClaims {
		if value == "mutated" {
			t.Fatal("schema projection changed builtin nonClaims")
		}
	}
}

func TestBranchRequiredMembersAndUnknownFieldsFailAtAdmission(t *testing.T) {
	for _, level := range []string{"root", "ref"} {
		fields := []string{"schemaVersion", "reportId", "branchRefs", "preexistingFailures", "nonClaims"}
		if level == "ref" {
			fields = []string{"evidenceRef", "expectedBranch", "nonClaims", "observedBranch", "refId", "refKind", "required"}
		}
		for _, field := range fields {
			for _, mode := range []string{"missing", "null"} {
				t.Run(level+"/"+field+"/"+mode, func(t *testing.T) {
					input := validBranchAuthorityInput("main")
					object := input
					if level == "ref" {
						object = input["branchRefs"].([]any)[0].(map[string]any)
					}
					if mode == "missing" {
						delete(object, field)
					} else {
						object[field] = nil
					}
					_, code, err := Build(input)
					if code != 1 || err == nil || !strings.Contains(err.Error(), field) {
						t.Fatalf("missing/null %s did not fail its admission: code=%d error=%v", field, code, err)
					}
				})
			}
		}
		input := validBranchAuthorityInput("main")
		object, context := input, "branch authority input"
		if level == "ref" {
			object = input["branchRefs"].([]any)[0].(map[string]any)
			context = "branch authority ref 1"
		}
		object["api_key="+strings.Repeat("a", 16)] = "opaque"
		_, code, err := Build(input)
		if code != 1 || err == nil || err.Error() != context+" has unsupported field(s): 1" {
			t.Fatalf("unknown field boundary drifted: code=%d error=%v", code, err)
		}
	}
}

func TestBranchIdentifiersAndNormalizedCollisions(t *testing.T) {
	for _, field := range []string{"reportId", "refId"} {
		for _, test := range []struct {
			value string
			valid bool
		}{
			{strings.Repeat("a", 256), true}, {strings.Repeat("a", 257), false},
			{" stable.id", false}, {"stable.id\n", false}, {"stable.2026-09-28", false},
			{"gh" + "p_" + strings.Repeat("a", 36), false},
		} {
			input := validBranchAuthorityInput("main")
			object := input
			if field == "refId" {
				object = input["branchRefs"].([]any)[0].(map[string]any)
			}
			object[field] = test.value
			_, _, err := Build(input)
			if (err == nil) != test.valid {
				t.Fatalf("identifier field=%s valid=%t error=%v", field, test.valid, err)
			}
		}
	}
	for _, mode := range []string{"ref-id", "root-trim", "ref-trim", "builtin-trim"} {
		t.Run(mode, func(t *testing.T) {
			input := validBranchAuthorityInput("main")
			switch mode {
			case "ref-id":
				other := validBranchAuthorityInput("feature/other")["branchRefs"].([]any)[0]
				input["branchRefs"] = append(input["branchRefs"].([]any), other)
			case "root-trim":
				input["preexistingFailures"] = []any{"same", " same "}
			case "ref-trim":
				input["branchRefs"].([]any)[0].(map[string]any)["nonClaims"] = []any{"same", " same "}
			case "builtin-trim":
				input["nonClaims"] = []any{" Branch authority reports do not mutate branch settings. "}
			}
			_, code, err := Build(input)
			if code != 1 || err == nil {
				t.Fatalf("collision did not fail admission: code=%d error=%v", code, err)
			}
			if mode == "ref-id" && err.Error() != "branch authority ref ids must be unique" {
				t.Fatalf("duplicate identifier failed at wrong boundary: %v", err)
			}
		})
	}
}

func TestBranchWireEvaluationTruthTableAndOrder(t *testing.T) {
	for _, test := range []struct {
		required, advisory, prior int
		code                      int
		state                     string
		rules                     []string
	}{
		{0, 0, 0, 0, "passed", []string{"passed", "passed", "passed"}},
		{0, 1, 0, 0, "passed", []string{"warning", "passed", "passed"}},
		{0, 0, 1, 1, "failed", []string{"passed", "failed", "passed"}},
		{1, 0, 0, 1, "failed", []string{"passed", "passed", "failed"}},
		{1, 1, 0, 1, "failed", []string{"warning", "passed", "failed"}},
		{0, 1, 1, 1, "failed", []string{"warning", "failed", "passed"}},
		{1, 0, 1, 1, "failed", []string{"passed", "failed", "failed"}},
		{1, 1, 1, 1, "failed", []string{"warning", "failed", "failed"}},
	} {
		input := validBranchAuthorityInput("main")
		required := input["branchRefs"].([]any)[0].(map[string]any)
		required["refId"] = "proofkit.test.z"
		advisory := validBranchAuthorityInput("main")["branchRefs"].([]any)[0].(map[string]any)
		advisory["refId"], advisory["required"] = "proofkit.test.a", false
		if test.required != 0 {
			required["observedBranch"] = "feature/required"
		}
		if test.advisory != 0 {
			advisory["observedBranch"] = "feature/advisory"
		}
		if test.prior != 0 {
			input["preexistingFailures"] = []any{"prior failure"}
		}
		input["branchRefs"] = []any{required, advisory}
		record, code, err := Build(input)
		if err != nil || code != test.code || record.State != test.state {
			t.Fatalf("required=%d advisory=%d prior=%d: code=%d state=%s error=%v", test.required, test.advisory, test.prior, code, record.State, err)
		}
		wantSummary := map[string]any{"advisoryDriftCount": test.advisory, "branchRefCount": 2, "requiredDriftCount": test.required}
		if !reflect.DeepEqual(record.Summary, wantSummary) {
			t.Fatalf("summary=%#v, want %#v", record.Summary, wantSummary)
		}
		wire, err := stablejson.Marshal(record.JSONValue())
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(wire, &decoded); err != nil {
			t.Fatal(err)
		}
		if len(decoded) != 8 || decoded["reportKind"] != "proofkit.branch-authority" || decoded["state"] != test.state {
			t.Fatalf("wire carrier drift: %s", wire)
		}
		diagnostics := decoded["diagnostics"].([]any)
		if len(diagnostics) != 3 || len(record.RuleResults) != 3 {
			t.Fatal("diagnostic or rule tuple length changed")
		}
		for index, key := range []string{"advisoryDriftRefIds", "branchRefs", "requiredDriftRefIds"} {
			if diagnostics[index].(map[string]any)["key"] != key {
				t.Fatal("diagnostic tuple order changed")
			}
		}
		refs := diagnostics[1].(map[string]any)["value"].([]any)
		if refs[0].(map[string]any)["refId"] != "proofkit.test.a" || refs[1].(map[string]any)["refId"] != "proofkit.test.z" {
			t.Fatal("refs are not sorted by exact identifier")
		}
		for _, drift := range []struct {
			index, count, ref int
			id                string
		}{{0, test.advisory, 0, "proofkit.test.a"}, {2, test.required, 1, "proofkit.test.z"}} {
			wantIDs := []any{}
			alignment := "aligned"
			if drift.count != 0 {
				wantIDs, alignment = []any{drift.id}, "drifted"
			}
			if !reflect.DeepEqual(diagnostics[drift.index].(map[string]any)["value"], wantIDs) || refs[drift.ref].(map[string]any)["alignment"] != alignment {
				t.Fatal("drift lists or alignment changed")
			}
		}
		messages := [3][2]string{
			{"no advisory branch drift", "advisory branch drift is visible but does not fail this report"},
			{"no caller preexisting branch authority failures", "caller supplied preexisting branch authority failures"},
			{"all required branch refs match caller expected branches", "required branch refs drifted from caller expected branches"},
		}
		counts := []int{test.advisory, test.prior, test.required}
		for index, id := range []string{"branch_authority.advisory_refs_visible", "branch_authority.preexisting_failures", "branch_authority.required_refs_aligned"} {
			if record.RuleResults[index].RuleID != id || record.RuleResults[index].Status != test.rules[index] || record.RuleResults[index].Message != messages[index][counts[index]] {
				t.Fatalf("rule tuple changed: %#v", record.RuleResults)
			}
		}
		slices.Reverse(input["branchRefs"].([]any))
		permuted, _, err := Build(input)
		if err != nil {
			t.Fatal(err)
		}
		other, err := stablejson.Marshal(permuted.JSONValue())
		if err != nil || string(other) != string(wire) {
			t.Fatal("ref permutation changed wire output")
		}
	}
}

func branchSchemaValue(t *testing.T, schema map[string]any, pointer string) any {
	t.Helper()
	value, err := jsonpointer.Select(schema, pointer)
	if err != nil {
		t.Fatalf("schema pointer %s: %v", pointer, err)
	}
	return value
}
