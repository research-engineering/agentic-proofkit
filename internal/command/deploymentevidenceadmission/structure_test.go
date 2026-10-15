package deploymentevidenceadmission

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func TestDeploymentOutputsSelectExactlyTheirStateBranch(t *testing.T) {
	fact := func(input map[string]any) map[string]any {
		return input["evidence"].(map[string]any)["facts"].([]any)[0].(map[string]any)
	}
	cases := []struct {
		name, state string
		blocked     bool
		mutate      func(map[string]any)
	}{
		{"passed", "passed", false, nil},
		{"temporary-endpoint", "passed", false, func(input map[string]any) {
			fact(input)["urls"] = []any{map[string]any{"endpointId": "proofkit.test.endpoint", "endpointKind": "temporary", "url": "https://demo.trycloudflare.com/proof",
				"expiresAt": "2026-01-01T00:00:00Z", "temporaryEndpointApprovalRef": "proofkit.test.approval", "replacementPlanRef": "proofkit.test.replacement"}}
		}},
		{"null-evidence", "blocked", true, func(input map[string]any) { input["evidence"] = nil }},
		{"missing-evidence-id", "blocked", true, func(input map[string]any) { delete(input["evidence"].(map[string]any), "evidenceId") }},
		{"unpinned-image", "failed", false, func(input map[string]any) { fact(input)["imageRefs"] = []any{"registry.example.test/proofkit:latest"} }},
		{"failed-and-blocked", "failed", true, func(input map[string]any) {
			evidence := input["evidence"].(map[string]any)
			evidence["facts"], evidence["foreign"] = []any{}, true
		}},
		{"secret-payload", "failed", false, func(input map[string]any) {
			input["rawOperatorEvidence"] = []any{map[string]any{"evidenceRef": "operator.note", "payload": map[string]any{"note": "api_key=synthetic-fixture-value"}}}
		}},
		{"builtin-claim-copy", "passed", false, func(input map[string]any) { input["nonClaims"] = []any{boundaryNonClaims[0]} }},
		{"empty-evidence", "failed", true, func(input map[string]any) {
			input["evidence"] = map[string]any{"facts": []any{false}, "evidenceId": "  ", "nested": map[string]any{"k": []any{nil}}}
		}},
	}
	branches := []struct {
		state   string
		blocked bool
	}{{"passed", false}, {"blocked", true}, {"failed", false}, {"failed", true}}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := validDeploymentEvidenceInput()
			if test.mutate != nil {
				test.mutate(input)
			}
			record, code, err := Build(input)
			if err != nil || record.State != test.state || (code == 0) != (test.state == "passed") {
				t.Fatalf("native phase changed: state=%s code=%d err=%v", record.State, code, err)
			}
			value := deploymentWireValue(t, record.JSONValue())
			if err := OutputShape().CheckGenerated(value, "report"); err != nil {
				t.Fatal(err)
			}
			for _, branch := range branches {
				matched := reportShape(branch.state, branch.blocked).CheckGenerated(value, "branch") == nil
				if matched != (branch.state == test.state && branch.blocked == test.blocked) {
					t.Fatalf("branch %s/%t selection=%t", branch.state, branch.blocked, matched)
				}
			}
			if err := ruleIDShape().CheckGenerated(value["reportId"], "reportId"); err != nil {
				t.Fatal(err)
			}
			claims := value["nonClaims"].([]any)
			if err := jsonshape.Array(canonicalTextShape(), len(boundaryNonClaims)+1).CheckGenerated(claims, "nonClaims"); err != nil {
				t.Fatal(err)
			}
			for _, claim := range boundaryNonClaims {
				if !slices.Contains(claims, any(claim)) {
					t.Fatalf("builtin claim missing: %s", claim)
				}
			}
		})
	}
}

func TestDeploymentOutputRejectsStateRuleDrift(t *testing.T) {
	record, _, err := Build(validDeploymentEvidenceInput())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"state":       func(value map[string]any) { value["state"] = "blocked" },
		"rule-status": func(value map[string]any) { rule(value, 1)["status"] = "failed" },
		"rule-message": func(value map[string]any) {
			rule(value, 0)["message"] = "deployment evidence admission state is failed"
		},
		"rule-key": func(value map[string]any) {
			rule(value, 2)["diagnostics"].([]any)[0].(map[string]any)["key"] = "failures"
		},
		"blocked-count": func(value map[string]any) { value["summary"].(map[string]any)["blockedReasonCount"] = json.Number("1") },
		"evidence-id":   func(value map[string]any) { value["summary"].(map[string]any)["evidenceId"] = " padded" },
		"extra":         func(value map[string]any) { value["summary"].(map[string]any)["foreign"] = true },
		"blocked-list": func(value map[string]any) {
			value["diagnostics"].([]any)[0].(map[string]any)["value"] = []any{"blocked"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := deploymentWireValue(t, record.JSONValue())
			mutate(value)
			if OutputShape().CheckGenerated(value, "report") == nil {
				t.Fatal("drifted report admitted")
			}
		})
	}
}

func TestDeploymentPolicyShapeAgreesWithNativeAdmission(t *testing.T) {
	type policyCase struct {
		name, class string
		mutate      func(map[string]any)
	}
	set := func(key string, value any) func(map[string]any) {
		return func(policy map[string]any) { policy[key] = value }
	}
	bounded := strings.Repeat("a", admit.MaxRuleIDBytes)
	cases := []policyCase{
		{"fixture", "accept", func(map[string]any) {}},
		{"padded-ids", "accept", set("requiredFactIds", []any{" \u3000proofkit.test.fact\t", "proofkit.test.fact"})},
		{"bounded-padded-id", "accept", set("requiredFactKinds", []any{"\u0085" + bounded + " "})},
		{"ids-only", "accept", set("requiredFactKinds", []any{})},
		{"kinds-only", "accept", set("requiredFactIds", []any{})},
		{"duplicate-text", "accept", set("requiredNonClaims", []any{"Same.", " Same."})},
		{"empty-optional-lists", "accept", func(policy map[string]any) {
			policy["forbiddenValueIndicators"], policy["temporaryEndpointHostSuffixes"] = []any{}, []any{}
		}},
		{"padded-text", "accept", set("expectedProofScope", "\tlocal ")},
		{"both-requirements-empty", "structural", func(policy map[string]any) {
			policy["requiredFactIds"], policy["requiredFactKinds"] = []any{}, []any{}
		}},
		{"bounded-id-exceeded", "structural", set("requiredFactIds", []any{" a" + bounded})},
		{"invalid-id", "structural", set("requiredFactKinds", []any{"1bad"})},
		{"blank-id", "structural", set("requiredFactKinds", []any{" "})},
		{"empty-required-claims", "structural", set("requiredNonClaims", []any{})},
		{"empty-local-indicators", "structural", set("localRefIndicators", []any{})},
		{"blank-indicator", "structural", set("forbiddenValueIndicators", []any{"\u3000"})},
		{"blank-text", "structural", set("expectedEvidenceSchema", " ")},
		{"non-boolean", "structural", set("requireDigestPinnedImageRefs", "true")},
		{"null-list", "structural", set("temporaryEndpointHostSuffixes", nil)},
		{"unknown", "structural", set("foreign", true)},
		{"secret-text", "native", set("expectedDeploymentClaim", "Bearer abcdefghijklmnopqrstuvwxyz")},
		{"timestamp-id", "native", set("requiredFactIds", []any{"fact.20240101"})},
		{"duplicate-suffix", "native", set("temporaryEndpointHostSuffixes", []any{"Example.com", "example.com"})},
		{"invalid-suffix", "native", set("temporaryEndpointHostSuffixes", []any{"bad..host"})},
		{"empty-normalized-indicator", "native", set("localRefIndicators", []any{"\u00ad"})},
	}
	for _, key := range policyKeys {
		cases = append(cases, policyCase{"missing-" + key, "structural", func(policy map[string]any) { delete(policy, key) }})
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := validDeploymentEvidenceInput()
			policy := input["policy"].(map[string]any)
			test.mutate(policy)
			_, nativeErr := admitPolicy(policy)
			_, _, buildErr := Build(input)
			if (nativeErr == nil) != (buildErr == nil) {
				t.Fatalf("policy refusal changed phase: policy=%v build=%v", nativeErr, buildErr)
			}
			structuralErr := policyStructuralError(policy)
			switch test.class {
			case "accept":
				if nativeErr != nil || structuralErr != nil {
					t.Fatalf("admitted policy diverged: native=%v structure=%v", nativeErr, structuralErr)
				}
			case "structural":
				if nativeErr == nil || structuralErr == nil {
					t.Fatalf("structural refusal diverged: native=%v structure=%v", nativeErr, structuralErr)
				}
			case "native":
				if nativeErr == nil || structuralErr != nil {
					t.Fatalf("native-only refusal changed owner: native=%v structure=%v", nativeErr, structuralErr)
				}
			}
		})
	}
}

func TestDeploymentTrimmedIDGrammarMatchesNativeNormalization(t *testing.T) {
	grammar, bound := trimmedIDShape(), trimmedIDBoundShape()
	values := []string{"a", "a.b", " a", "a\t", "\u3000a.b-c:d_e\u0085", "", " ", "a b", "a..b", "1a", "a.", "-a", "a/b"}
	for _, length := range []int{admit.MaxRuleIDBytes - 1, admit.MaxRuleIDBytes, admit.MaxRuleIDBytes + 1} {
		values = append(values, " "+strings.Repeat("a", length)+"\u2028")
	}
	for _, value := range values {
		_, nativeErr := sortedRuleIDs([]any{value}, "ids", true)
		structural := grammar.CheckGenerated(value, "id") == nil && bound.CheckGenerated(value, "id") == nil
		if (nativeErr == nil) != structural {
			t.Fatalf("trimmed ID %q diverged: native=%v structure=%t", value, nativeErr, structural)
		}
	}
}

func TestDeploymentCallerJSONKeysMatchNativeScanner(t *testing.T) {
	key := jsonshape.StringGrammar(`[^\x00-\x1f\x7f]+`)
	if !reflect.DeepEqual(callerJSONKeyStructure(), nestedSchema(key)) {
		t.Fatal("caller JSON key structure drifted")
	}
	for _, name := range []string{"", "\x00", "a\x1fb", "\x7f", "\n", " ", "a", "\u0085", "\u009f", "\u00e9", "api_key"} {
		for _, place := range []string{"evidence", "payload", "payload-array"} {
			input := validDeploymentEvidenceInput()
			nested := map[string]any{"outer": map[string]any{name: "value"}}
			switch place {
			case "evidence":
				input["evidence"].(map[string]any)["metadata"] = nested
			case "payload":
				input["rawOperatorEvidence"] = []any{map[string]any{"evidenceRef": "operator.note", "payload": nested}}
			case "payload-array":
				input["rawOperatorEvidence"] = []any{map[string]any{"evidenceRef": "operator.note", "payload": []any{nil, []any{nested}}}}
			}
			_, _, err := Build(input)
			if (err == nil) != (key.CheckGenerated(name, "key") == nil) {
				t.Fatalf("%s key %q diverged: %v", place, name, err)
			}
		}
	}
	for _, value := range []any{nil, false, json.Number("-1.5e3"), "", []any{}, map[string]any{}} {
		input := validDeploymentEvidenceInput()
		input["rawOperatorEvidence"] = []any{map[string]any{"evidenceRef": "operator.note", "payload": value}}
		if _, _, err := Build(input); err != nil {
			t.Fatalf("caller payload %v refused: %v", value, err)
		}
	}
}

func TestDeploymentRootStructureMatchesNativeRequiredMembers(t *testing.T) {
	schema := InputStructure()
	properties := schema["properties"].(map[string]any)
	keys := make([]string, 0, len(properties))
	for key := range properties {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, inputKeys) || !reflect.DeepEqual(schema["required"], []any{"admissionId", "evidence", "nonClaims", "policy", "schemaVersion"}) {
		t.Fatalf("root inventory drifted: %v %v", keys, schema["required"])
	}
	for name, mutate := range map[string]func(map[string]any){
		"missing-evidence":     func(input map[string]any) { delete(input, "evidence") },
		"scalar-evidence":      func(input map[string]any) { input["evidence"] = "evidence" },
		"array-evidence":       func(input map[string]any) { input["evidence"] = []any{} },
		"object-operator-list": func(input map[string]any) { input["rawOperatorEvidence"] = map[string]any{} },
		"scalar-operator":      func(input map[string]any) { input["rawOperatorEvidence"] = []any{"note"} },
		"missing-payload": func(input map[string]any) {
			input["rawOperatorEvidence"] = []any{map[string]any{"evidenceRef": "operator.note"}}
		},
		"unknown-operator-field": func(input map[string]any) {
			input["rawOperatorEvidence"] = []any{map[string]any{"evidenceRef": "operator.note", "payload": nil, "x": 1}}
		},
		"blank-operator-ref": func(input map[string]any) {
			input["rawOperatorEvidence"] = []any{map[string]any{"evidenceRef": " ", "payload": nil}}
		},
		"empty-nonclaims": func(input map[string]any) { input["nonClaims"] = []any{} },
		"schema-version":  func(input map[string]any) { input["schemaVersion"] = json.Number("1.0") },
	} {
		input := validDeploymentEvidenceInput()
		mutate(input)
		if _, _, err := Build(input); err == nil {
			t.Fatalf("%s was admitted natively", name)
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"absent-operator": func(input map[string]any) { delete(input, "rawOperatorEvidence") },
		"null-operator":   func(input map[string]any) { input["rawOperatorEvidence"] = nil },
		"null-evidence":   func(input map[string]any) { input["evidence"] = nil },
	} {
		input := validDeploymentEvidenceInput()
		mutate(input)
		if _, _, err := Build(input); err != nil {
			t.Fatalf("%s was refused natively: %v", name, err)
		}
	}
	first, second := InputStructure(), InputStructure()
	first["properties"].(map[string]any)["policy"].(map[string]any)["required"] = []any{}
	if !reflect.DeepEqual(second, InputStructure()) || !reflect.DeepEqual(OutputStructure(), OutputStructure()) {
		t.Fatal("structure projection is not detached and deterministic")
	}
}

// PolicyStructure adds the trimmed-ID bound and the nonempty disjunction.
func policyStructuralError(policy map[string]any) error {
	if _, err := PolicyShape().Admit(policy, "policy"); err != nil {
		return err
	}
	nonempty := false
	for _, key := range []string{"requiredFactIds", "requiredFactKinds"} {
		values := policy[key].([]any)
		nonempty = nonempty || len(values) > 0
		for _, value := range values {
			if err := trimmedIDBoundShape().CheckGenerated(value, key); err != nil {
				return err
			}
		}
	}
	if !nonempty {
		return fmt.Errorf("policy declares no required facts")
	}
	return nil
}

func rule(value map[string]any, index int) map[string]any {
	return value["ruleResults"].([]any)[index].(map[string]any)
}

func deploymentWireValue(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
