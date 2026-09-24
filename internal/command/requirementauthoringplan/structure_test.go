package requirementauthoringplan

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func authoringWire(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	return wire.(map[string]any)
}

func TestAuthoringStructuresPreserveOutcomeAndPayloadAlgebra(t *testing.T) {
	for _, tc := range []struct {
		name, state, comparison, transition string
		mutate                              func(map[string]any)
	}{
		{"passed", "passed", "compared", "passed", func(map[string]any) {}},
		{"source failed", "failed", "skipped_source_admission", "skipped", func(v map[string]any) {
			candidateMember(v)["fields"].(map[string]any)["proofBindingRefs"] = []any{}
		}},
		{"transition failed", "failed", "compared", "failed", func(v map[string]any) {
			v["candidateRequirementSource"] = groupedTestSource(candidateRequirement())
		}},
		{"composition failed", "failed", "compared", "passed", func(v map[string]any) { firstUpdate(v)["operation"] = "modify" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := validInput()
			tc.mutate(input)
			if _, err := authoringInputShape.Admit(input, "input"); err != nil {
				t.Fatal(err)
			}
			output, exit, err := Build(input)
			if err != nil || output["state"] != tc.state || (exit == 0) != (tc.state == "passed") {
				t.Fatalf("outcome drift: exit=%d err=%v output=%#v", exit, err, output)
			}
			if output["sourceComparisonState"] != tc.comparison || output["summary"].(map[string]any)["transitionAdmissionState"] != tc.transition {
				t.Fatalf("comparison or transition state drift: comparison=%v summary=%#v", output["sourceComparisonState"], output["summary"])
			}
			if (output["changedSourcePlanes"] == nil) != (tc.comparison == "skipped_source_admission") || (output["nonAuthoritativeAdmissionPreview"] != nil) != (tc.state == "passed") {
				t.Fatal("failed admission fabricated a comparison or preview")
			}
			candidate := output["candidateChangeSet"].([]any)[0].(map[string]any)
			_, present := candidate["candidateRequirement"]
			_, omitted := candidate["candidateRequirementOmitted"]
			if present == omitted || present != (tc.state == "passed") {
				t.Fatal("candidate payload must have exactly one outcome-bound alternative")
			}
			wire := authoringWire(t, output)
			admitted, err := authoringOutputShape.Admit(wire, "output")
			if err != nil || !reflect.DeepEqual(admitted, wire) {
				t.Fatalf("owner output does not re-admit unchanged: %v", err)
			}
		})
	}
}

func TestAuthoringInputStructurePresenceAndCanonicalBoundary(t *testing.T) {
	base := validInput()
	for key := range base {
		for _, mode := range []string{"missing", "null", "wrong type"} {
			t.Run(key+"/"+mode, func(t *testing.T) {
				v := validInput()
				switch mode {
				case "missing":
					delete(v, key)
				case "null":
					v[key] = nil
				default:
					v[key] = false
				}
				if _, _, err := Build(v); err == nil {
					t.Fatal("invalid root admitted")
				}
			})
		}
	}
	for _, version := range []any{json.Number("1"), json.Number("2.0"), 2, float64(2)} {
		v := validInput()
		v["schemaVersion"] = version
		if _, _, err := Build(v); err == nil {
			t.Fatalf("noncanonical/wrong version admitted: %#v", version)
		}
	}
	for _, digest := range []any{nil, " " + validDigest() + " "} {
		v := validInput()
		v["authoringRefs"].([]any)[0].(map[string]any)["digest"] = digest
		out, exit, err := Build(v)
		if err != nil || exit != 0 {
			t.Fatalf("valid nullable/normalized digest rejected: %v", err)
		}
		got := out["authoringRefs"].([]any)[0].(map[string]any)["digest"]
		if (digest == nil && got != nil) || (digest != nil && got != validDigest()) {
			t.Fatal("digest presence/normalization changed")
		}
	}
	v := validInput()
	delete(v["authoringRefs"].([]any)[0].(map[string]any), "digest")
	if _, exit, err := Build(v); err != nil || exit != 0 {
		t.Fatalf("optional digest became required: %v", err)
	}
	v = validInput()
	v["mode"] = " pull_request_design "
	if _, _, err := Build(v); err == nil {
		t.Fatal("enum whitespace became accepted")
	}
	owned, err := admitInput(base)
	if err != nil {
		t.Fatal(err)
	}
	before := authoringWire(t, owned.CandidateRequirementValue)
	candidateMember(base)["statementCompletion"] = "Changed after admission."
	if !reflect.DeepEqual(before, authoringWire(t, owned.CandidateRequirementValue)) {
		t.Fatal("candidate source retained mutable caller input")
	}
}

func TestAuthoringStructuresRejectNestedCorruptionAndAuthorityEscalation(t *testing.T) {
	ref := func(v map[string]any) map[string]any { return v["authoringRefs"].([]any)[0].(map[string]any) }
	obligation := func(v map[string]any) map[string]any {
		return firstUpdate(v)["declaredProofObligations"].([]any)[0].(map[string]any)
	}
	for _, selectObject := range []func(map[string]any) map[string]any{ref, firstUpdate, obligation} {
		for key := range selectObject(validInput()) {
			if key == "digest" {
				continue
			}
			v := validInput()
			delete(selectObject(v), key)
			if _, _, err := Build(v); err == nil {
				t.Fatalf("missing nested %s admitted", key)
			}
		}
		v := validInput()
		selectObject(v)["unexpected"] = true
		if _, _, err := Build(v); err == nil {
			t.Fatal("unknown nested field admitted")
		}
	}
	v := validInput()
	const unknownRef = "private.caller.reference"
	firstUpdate(v)["sourceRefIds"] = []any{unknownRef}
	if _, _, err := Build(v); err == nil || strings.Contains(err.Error(), unknownRef) {
		t.Fatalf("unknown ref must reject without echo: %v", err)
	}
	out, exit, err := Build(validInput())
	if err != nil || exit != 0 {
		t.Fatal(err)
	}
	candidate := func(v map[string]any) map[string]any { return v["candidateChangeSet"].([]any)[0].(map[string]any) }
	mutations := map[string]func(map[string]any){
		"payload alternatives": func(v map[string]any) { candidate(v)["candidateRequirementOmitted"] = omittedCandidateMessage },
		"neither payload":      func(v map[string]any) { delete(candidate(v), "candidateRequirement") },
		"atomic lifecycle":     func(v map[string]any) { delete(candidate(v)["candidateRequirement"].(map[string]any), "lifecycle") },
		"authority": func(v map[string]any) {
			v["nonAuthoritativeAdmissionPreview"].(map[string]any)["authority"] = "approved"
		},
		"review false": func(v map[string]any) { v["wholeCandidateOwnerReviewRequired"] = false },
		"executed witness": func(v map[string]any) {
			v["summary"].(map[string]any)["executedWitnessCountNonClaim"] = json.Number("1")
		},
		"wrong action variant": func(v map[string]any) { v["ownerReviewPlan"].([]any)[0].(map[string]any)["actionKind"] = "ask_owner" },
		"extra action field":   func(v map[string]any) { v["ownerReviewPlan"].([]any)[2].(map[string]any)["instruction"] = "Unexpected" },
		"missing precondition": func(v map[string]any) { v["promotionPreconditions"] = v["promotionPreconditions"].([]any)[:3] },
		"wrong rule order":     func(v map[string]any) { rows := v["ruleResults"].([]any); rows[0], rows[1] = rows[1], rows[0] },
		"unknown output":       func(v map[string]any) { v["unexpected"] = true },
	}
	for key := range out {
		mutations["missing "+key] = func(v map[string]any) { delete(v, key) }
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			wire := authoringWire(t, out)
			mutate(wire)
			if _, err := authoringOutputShape.Admit(wire, "output"); err == nil {
				t.Fatal("corrupted output admitted")
			}
		})
	}
}

func TestAuthoringPreservesEveryCandidateProjection(t *testing.T) {
	for _, failed := range []bool{false, true} {
		input := sharedOwnerInput()
		input["candidateRequirementSource"].(map[string]any)["profiles"].([]any)[0].(map[string]any)["fields"].(map[string]any)["riskClass"] = "critical"
		if failed {
			firstUpdate(input)["operation"] = "add"
		}
		output, exit, err := Build(input)
		if err != nil || (exit != 0) != failed {
			t.Fatalf("candidate fixture failed unexpectedly: exit=%d err=%v", exit, err)
		}
		expected := input["candidateUpdates"].([]any)
		actual := output["candidateChangeSet"].([]any)
		if len(expected) != 2 || len(actual) != len(expected) || output["summary"].(map[string]any)["candidateUpdateCount"] != len(expected) {
			t.Fatal("complete candidate projection lost or invented an update")
		}
		for index, raw := range expected {
			row := cloneObject(actual[index].(map[string]any))
			if failed {
				if row["candidateRequirementOmitted"] != omittedCandidateMessage {
					t.Fatal("failed row must carry its omission marker")
				}
				delete(row, "candidateRequirementOmitted")
			} else {
				payload, ok := row["candidateRequirement"].(map[string]any)
				if !ok || payload["requirementId"] != raw.(map[string]any)["requirementId"] || payload["riskClass"] != "critical" {
					t.Fatal("candidate row lost its own effective requirement")
				}
				delete(row, "candidateRequirement")
			}
			assertStableJSONEqual(t, "complete ordered candidate metadata", raw, row)
		}
	}
}

func TestAuthoringPathsPreserveCallerIdentity(t *testing.T) {
	for _, suffix := range []string{"", " ", "  "} {
		input := validInput()
		ref := input["authoringRefs"].([]any)[0].(map[string]any)
		refPath := "docs/designs/test-feature.md" + suffix
		evidencePath := "proofkit/requirement-bindings.json" + suffix
		ref["path"] = refPath
		firstUpdate(input)["declaredProofObligations"].([]any)[0].(map[string]any)["evidenceRefs"] = []any{evidencePath}
		output, exit, err := Build(input)
		if err != nil || exit != 0 {
			t.Fatalf("valid POSIX path rejected: %v", err)
		}
		assertStableJSONEqual(t, "path and digest-bound ref", ref, output["authoringRefs"].([]any)[0])
		actual := output["candidateChangeSet"].([]any)[0].(map[string]any)["declaredProofObligations"].([]any)[0].(map[string]any)["evidenceRefs"]
		assertStableJSONEqual(t, "literal evidence path", []any{evidencePath}, actual)
	}
	for _, path := range []string{".git/config", "../outside", "docs/file\n", "docs/file\t"} {
		input := validInput()
		input["authoringRefs"].([]any)[0].(map[string]any)["path"] = path
		if _, _, err := Build(input); err == nil {
			t.Fatal("unsafe authoring path admitted")
		}
	}
}
