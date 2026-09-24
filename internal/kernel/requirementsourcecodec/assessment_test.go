package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestByteAndValueAssessmentsPreserveStrictModel(t *testing.T) {
	payload := mustPayload(t)
	strict, err := Parse(payload)
	if err != nil {
		t.Fatal(err)
	}
	byteResult, err := Assess(payload)
	if err != nil {
		t.Fatal(err)
	}
	value := decodedTestValue(t, payload)
	valueResult, err := AssessValue(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range []requirementsourcemodel.Assessment{byteResult.Assessment, valueResult} {
		model, ok := result.Model()
		if !ok || !sameModel(model, strict.Model) || len(result.Violations()) != 0 {
			t.Fatal("byte/value assessment changed the strict admitted model")
		}
	}
	if !reflect.DeepEqual(byteResult.SourceMap, strict.SourceMap) {
		t.Fatal("byte assessment changed original source coordinates")
	}
	wantSummary, _ := valueResult.Summary()
	value.(map[string]any)["sourceNonClaims"].([]any)[0] = "Caller mutation."
	for index := range payload {
		payload[index] = ' '
	}
	if summary, _ := valueResult.Summary(); !reflect.DeepEqual(summary, wantSummary) {
		t.Fatal("value assessment aliases caller state")
	}
	if summary, _ := byteResult.Assessment.Summary(); !reflect.DeepEqual(summary, wantSummary) {
		t.Fatal("byte assessment aliases caller state")
	}
}

func TestAssessRetainsPolicyFailuresWithoutModel(t *testing.T) {
	payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		groups := root["groups"].([]any)
		for _, rawGroup := range groups {
			group := rawGroup.(map[string]any)
			if group["groupId"] != "RGRP-CODEC-REQUESTS" {
				continue
			}
			member := group["members"].([]any)[0].(map[string]any)
			member["fields"].(map[string]any)["proofBindingRefs"] = []any{}
		}
		policy := root["profiles"].([]any)[0].(map[string]any)["fields"].(map[string]any)["updatePolicy"].(map[string]any)
		policy["requiresImpactDeclaration"] = false
		policy["requiresProofBindingReview"] = false
	})
	byteResult, err := Assess(payload)
	if err != nil {
		t.Fatal(err)
	}
	valueResult, err := AssessValue(decodedTestValue(t, payload))
	if err != nil {
		t.Fatal(err)
	}
	wantCodes := []string{"missing_proof_binding", "impact_review_required", "proof_binding_review_required", "impact_review_required", "proof_binding_review_required"}
	gotCodes := []string{}
	for _, failure := range byteResult.Assessment.Violations() {
		gotCodes = append(gotCodes, failure.Code)
	}
	if !reflect.DeepEqual(gotCodes, wantCodes) {
		t.Fatalf("policy results differ: codes = %v, want %v", gotCodes, wantCodes)
	}
	assertAssessmentObservationsEqual(t, byteResult.Assessment, valueResult)
	for _, result := range []requirementsourcemodel.Assessment{byteResult.Assessment, valueResult} {
		if _, ok := result.Model(); ok {
			t.Fatal("failed assessment exposed a usable model")
		}
		if _, ok := result.Summary(); !ok {
			t.Fatal("failed assessment lost its report operands")
		}
	}
	if _, err := Parse(payload); ErrorCode(err) != "missing_proof_binding" {
		t.Fatalf("strict first error changed: %v", err)
	}
}

func TestAssessmentErrorsKeepOnlyTheirActualCoordinateAuthority(t *testing.T) {
	payload := mutateRoot(t, mustPayload(t), func(root map[string]any) { root["sourceId"] = "not a valid identifier" })
	_, byteErr := Assess(payload)
	_, valueErr := AssessValue(decodedTestValue(t, payload))
	if ErrorCode(byteErr) != "invalid_id" || ErrorCode(valueErr) != "invalid_id" {
		t.Fatalf("byte error = %v, value error = %v", byteErr, valueErr)
	}
	byteDiagnostic := byteErr.(*Error).Diagnostic()
	valueDiagnostic := valueErr.(*Error).Diagnostic()
	if byteDiagnostic.CoordinateState != "scalar" || byteDiagnostic.Start == nil || byteDiagnostic.End == nil || byteDiagnostic.Span.End <= byteDiagnostic.Span.Start {
		t.Fatalf("byte error lost lexical coordinates: %#v", byteDiagnostic)
	}
	if valueDiagnostic.Path != byteDiagnostic.Path || valueDiagnostic.CoordinateState != "unavailable" || valueDiagnostic.Start != nil || valueDiagnostic.End != nil || valueDiagnostic.Span != (ByteSpan{}) {
		t.Fatalf("value error fabricated source coordinates: %#v", valueDiagnostic)
	}
}

func TestAssessRejectsFramingAndLaterStructuralFailures(t *testing.T) {
	payload := mustPayload(t)
	for _, input := range [][]byte{duplicateRootField(t, payload, "sourceId"), append(append([]byte{}, payload...), []byte("{}")...)} {
		_, strictErr := Parse(input)
		result, err := Assess(input)
		if err == nil || ErrorCode(err) != ErrorCode(strictErr) || len(result.SourceMap.Pointers()) != 0 {
			t.Fatalf("raw admission drift: strict = %v, assessment = %v", strictErr, err)
		}
		assertAssessmentObservationsEqual(t, result.Assessment, requirementsourcemodel.Assessment{})
	}
	payload = mutateRoot(t, payload, func(root map[string]any) {
		policy := root["profiles"].([]any)[0].(map[string]any)["fields"].(map[string]any)["updatePolicy"].(map[string]any)
		policy["requiresImpactDeclaration"] = false
		root["scenarios"].([]any)[0].(map[string]any)["requirementIds"] = []any{"REQ-MISSING"}
	})
	result, err := Assess(payload)
	if ErrorCode(err) != "dangling_requirement_ref" || len(result.SourceMap.Pointers()) != 0 {
		t.Fatalf("structurally invalid source received an assessment: %v", err)
	}
	assertAssessmentObservationsEqual(t, result.Assessment, requirementsourcemodel.Assessment{})
}

func decodedTestValue(t *testing.T, source []byte) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	var result any
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

type forbiddenValueMarshaler struct{ calls *int }

func (value forbiddenValueMarshaler) MarshalJSON() ([]byte, error) {
	*value.calls++
	return []byte(`"proofkit.fake"`), nil
}

func TestAssessValueRejectsNonJSONRepresentationsWithoutCustomExecution(t *testing.T) {
	calls := 0
	for _, value := range []any{2, float64(2), json.Number("2.0"), json.Number("2e0"), json.RawMessage("2"), forbiddenValueMarshaler{&calls}} {
		root := decodedTestValue(t, mustPayload(t)).(map[string]any)
		root["schemaVersion"] = value
		result, err := AssessValue(root)
		if err == nil {
			t.Fatalf("accepted noncanonical input of type %T", value)
		}
		assertAssessmentObservationsEqual(t, result, requirementsourcemodel.Assessment{})
		if typed, ok := err.(*Error); !ok || typed.Diagnostic().CoordinateState != "unavailable" {
			t.Fatalf("invalid value error = %v", err)
		}
	}
	if calls != 0 {
		t.Fatal("value admission executed a caller marshaler")
	}
	root := decodedTestValue(t, mustPayload(t)).(map[string]any)
	root["sourceId"] = root
	if _, err := AssessValue(root); ErrorCode(err) != "invalid_type" {
		t.Fatalf("cyclic value was not bounded by its grammar: %v", err)
	}
}

func assertAssessmentObservationsEqual(t *testing.T, left, right requirementsourcemodel.Assessment) {
	t.Helper()
	leftModel, leftAvailable := left.Model()
	rightModel, rightAvailable := right.Model()
	leftSummary, leftAdmitted := left.Summary()
	rightSummary, rightAdmitted := right.Summary()
	if leftAvailable != rightAvailable || leftAdmitted != rightAdmitted ||
		!sameModel(leftModel, rightModel) || !reflect.DeepEqual(leftSummary, rightSummary) ||
		!reflect.DeepEqual(left.Violations(), right.Violations()) {
		t.Fatal("assessment contract observations differ")
	}
}

func TestAssessValueRejectsInvalidUTF8AndRedactsUnknownKeys(t *testing.T) {
	root := decodedTestValue(t, mustPayload(t)).(map[string]any)
	root["sourceNonClaims"] = []any{string([]byte{'x', 0xff})}
	if _, err := AssessValue(root); ErrorCode(err) != "invalid_utf8" {
		t.Fatalf("invalid UTF8 coerced: %v", err)
	}
	const sentinel = "api_key=private-value-sentinel"
	root = decodedTestValue(t, mustPayload(t)).(map[string]any)
	delete(root, "kind")
	root[sentinel] = true
	_, err := AssessValue(root)
	if err == nil || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("unknown field was accepted or disclosed: %v", err)
	}
}
