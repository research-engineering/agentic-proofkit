package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
	model "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestZeroDefaultsPreserveWholeModelsAndLexicalOwnership(t *testing.T) {
	draft := testDraft()
	draft.Groups[0].Members[0].Fields.ExternalNonClaimRefs = model.Own([]string{})
	draft.Groups[1].Members[0].Fields.UpdatePolicy.Value.RequiresImpactDeclaration = false
	draft.Groups[1].Members[0].Fields.UpdatePolicy.Value.RequiresProofBindingReview = false
	want, err := model.Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}
	sparse, err := Format(want)
	if err != nil {
		t.Fatal(err)
	}
	expanded := expandZeroDefaults(t, sparse)
	for _, input := range [][]byte{sparse, expanded} {
		parsed, err := Parse(input)
		if err != nil || !projectionsEqual(parsed.Model, want) {
			t.Fatalf("defaults changed a complete model projection: %v", err)
		}
		formatted, err := Format(parsed.Model)
		if err != nil || !bytes.Equal(formatted, sparse) {
			t.Fatalf("default normalization is not canonical: %v", err)
		}
		assertFuzzSourceMap(t, input, parsed.SourceMap)
	}
	parsed, err := Parse(sparse)
	if err != nil {
		t.Fatal(err)
	}
	// Normalized group order is deferred, requests, superseded.
	for _, pointer := range []string{
		"/groups/0/members/0/fields/updatePolicy/requiresImpactDeclaration",
		"/groups/0/members/0/fields/updatePolicy/requiresProofBindingReview",
		"/groups/1/members/0/fields/lifecycle/evidenceRefs",
		"/groups/1/members/0/fields/lifecycle/replacementRequirementIds",
	} {
		if _, exists := parsed.SourceMap.Location(pointer); exists {
			t.Fatalf("omitted default has an invented exact token at %s", pointer)
		}
		full, err := Parse(expanded)
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := full.SourceMap.Location(pointer); !exists {
			t.Fatalf("explicit zero lost its original token at %s", pointer)
		}
	}
	for pointer, token := range map[string]string{
		"/groups/1/members/0/fields/externalNonClaimRefs": "[]",
		"/groups/1/members/0/fields/deferral":             "null",
	} {
		location, exists := parsed.SourceMap.Location(pointer)
		if !exists || string(sparse[location.ValueSpan.Start:location.ValueSpan.End]) != token {
			t.Fatalf("presence-bearing metadata owner disappeared at %s", pointer)
		}
	}
}

func TestOptionalWireDefaultsRejectNullAndWrongTypes(t *testing.T) {
	payload := expandZeroDefaults(t, mustPayload(t))
	for _, pointer := range []string{
		"/sourceNonClaimRefs", "/nonClaimDefinitions", "/vocabulary", "/derivations", "/profiles", "/scenarios",
		"/groups/1/members/0/fields/lifecycle/replacementRequirementIds",
		"/groups/1/members/0/fields/lifecycle/evidenceRefs",
		"/profiles/0/fields/updatePolicy/requiresImpactDeclaration",
		"/profiles/0/fields/updatePolicy/requiresProofBindingReview",
	} {
		for _, value := range []any{nil, "not-a-declared-zero"} {
			changed := mutateRoot(t, payload, func(root map[string]any) {
				parent, key := zeroDefaultParent(t, root, pointer)
				parent[key] = value
			})
			_, err := Parse(changed)
			code := "invalid_type"
			if value == nil {
				code = "invalid_null"
			}
			assertDiagnostic(t, err, code, pointer)
		}
	}
}

func TestZeroDefaultsDoNotRelaxRequiredNeighborsOrBlockingReview(t *testing.T) {
	payload := mustPayload(t)
	for _, pointer := range []string{
		"/schemaVersion", "/kind", "/sourceId", "/specPackagePath", "/sourceNonClaims", "/groups",
		"/groups/1/members/0/fields/lifecycle/state", "/profiles/0/fields/updatePolicy/reviewOwnerId",
	} {
		changed := mutateRoot(t, payload, func(root map[string]any) {
			parent, key := zeroDefaultParent(t, root, pointer)
			delete(parent, key)
		})
		_, err := Parse(changed)
		assertDiagnostic(t, err, "missing_field", pointer)
	}
	for key, code := range map[string]string{
		"requiresImpactDeclaration": "impact_review_required", "requiresProofBindingReview": "proof_binding_review_required",
	} {
		changed := mutateRoot(t, payload, func(root map[string]any) {
			policy, err := jsonpointer.Select(root, "/profiles/0/fields/updatePolicy")
			if err != nil {
				t.Fatal(err)
			}
			delete(policy.(map[string]any), key)
		})
		result, err := Parse(changed)
		if ErrorCode(err) != code || !reflect.DeepEqual(result, Result{}) {
			t.Fatalf("default false bypassed a blocking review requirement: %v", err)
		}
	}
}

func TestEmptyJSONValueKeepsOwnedEmptyPointersAndNonzeroValues(t *testing.T) {
	empty := []string{}
	for _, value := range []any{&empty, json.RawMessage("null"), true, "value", []string{"value"}, struct{}{}} {
		if emptyJSONValue(reflect.ValueOf(value)) {
			t.Fatalf("nonempty or presence-bearing value %T was omitted", value)
		}
	}
	for _, value := range []any{empty, []string(nil), json.RawMessage(nil), false, "", 0, map[string]string{}} {
		if !emptyJSONValue(reflect.ValueOf(value)) {
			t.Fatalf("declared zero %T was not recognized", value)
		}
	}
}

func expandZeroDefaults(t *testing.T, payload []byte) []byte {
	t.Helper()
	return mutateRoot(t, payload, func(root map[string]any) {
		for _, key := range []string{"sourceNonClaimRefs", "nonClaimDefinitions", "vocabulary", "derivations", "profiles", "scenarios"} {
			if _, exists := root[key]; !exists {
				root[key] = []any{}
			}
		}
		visit := func(fields map[string]any) {
			if value, exists := fields["lifecycle"].(map[string]any); exists {
				for _, key := range []string{"replacementRequirementIds", "evidenceRefs"} {
					if _, exists := value[key]; !exists {
						value[key] = []any{}
					}
				}
			}
			if value, exists := fields["updatePolicy"].(map[string]any); exists {
				for _, key := range []string{"requiresImpactDeclaration", "requiresProofBindingReview"} {
					if _, exists := value[key]; !exists {
						value[key] = false
					}
				}
			}
		}
		for _, profile := range root["profiles"].([]any) {
			visit(profile.(map[string]any)["fields"].(map[string]any))
		}
		for _, group := range root["groups"].([]any) {
			for _, member := range group.(map[string]any)["members"].([]any) {
				visit(member.(map[string]any)["fields"].(map[string]any))
			}
		}
	})
}

func zeroDefaultParent(t *testing.T, root map[string]any, pointer string) (map[string]any, string) {
	t.Helper()
	for index := len(pointer) - 1; index >= 0; index-- {
		if pointer[index] == '/' {
			parent, err := jsonpointer.Select(root, pointer[:index])
			if err != nil {
				t.Fatal(err)
			}
			return parent.(map[string]any), pointer[index+1:]
		}
	}
	t.Fatal("test pointer has no object field")
	return nil, ""
}
