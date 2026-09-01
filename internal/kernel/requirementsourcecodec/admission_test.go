package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestParseDiagnosticsDoNotDiscloseCallerTextOrDynamicKeys(t *testing.T) {
	const sentinel = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	tests := [][]byte{
		mutateRoot(t, mustPayload(t), func(root map[string]any) { root[sentinel] = true }),
		mutateRoot(t, mustPayload(t), func(root map[string]any) {
			scenarios := root["scenarios"].([]any)
			examples := scenarios[0].(map[string]any)["examples"].([]any)
			examples[0].(map[string]any)["values"].(map[string]any)[sentinel] = true
		}),
		mutateRoot(t, mustPayload(t), func(root map[string]any) {
			definitions := root["nonClaimDefinitions"].([]any)
			definitions[0].(map[string]any)["statement"] = "token=" + sentinel
		}),
	}
	for index, payload := range tests {
		_, err := Parse(payload)
		if err == nil {
			t.Fatalf("case %d: Parse() unexpectedly passed", index)
		}
		diagnostic, ok := err.(*Error)
		if !ok {
			t.Fatalf("case %d: error type = %T", index, err)
		}
		if strings.Contains(err.Error(), sentinel) || strings.Contains(diagnostic.Diagnostic().Path, sentinel) {
			t.Fatalf("case %d: diagnostic disclosed caller text: %v", index, err)
		}
	}
}

func TestPreShapeDiagnosticsDoNotDiscloseUnknownKeys(t *testing.T) {
	const sentinel = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	payload := []byte(`{"` + sentinel + `":` + strings.Repeat("[", defaultMaxNesting+1) + `0` + strings.Repeat("]", defaultMaxNesting+1) + `}`)
	_, err := Parse(payload)
	if ErrorCode(err) != "nesting_limit_exceeded" {
		t.Fatalf("Parse() error = %v", err)
	}
	diagnostic := err.(*Error).Diagnostic()
	if strings.Contains(err.Error(), sentinel) || strings.Contains(diagnostic.Path, sentinel) || !strings.HasPrefix(diagnostic.Path, "/<unknown>") {
		t.Fatalf("pre-shape diagnostic disclosed caller key: %#v", diagnostic)
	}
}

func TestParseDiagnosticsRedactSemanticEntityIDsAndResolveExactSpan(t *testing.T) {
	const definitionID = "NCL-CODEC-UNREFERENCED"
	payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		definitions := root["nonClaimDefinitions"].([]any)
		root["nonClaimDefinitions"] = append(definitions, map[string]any{
			"nonClaimId": definitionID,
			"statement":  "This declaration is intentionally unreferenced.",
		})
	})
	_, err := Parse(payload)
	assertDiagnostic(t, err, "unreferenced_definition", "/nonClaimDefinitions/4")
	diagnostic := err.(*Error).Diagnostic()
	if strings.Contains(err.Error(), definitionID) || strings.Contains(diagnostic.Path, definitionID) || !bytes.Contains(payload[diagnostic.Span.Start:diagnostic.Span.End], []byte(`"nonClaimId":"`+definitionID+`"`)) {
		t.Fatalf("definition diagnostic is not identity-safe and exact: %#v", diagnostic)
	}

	requirementPayload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		groups := root["groups"].([]any)
		members := groups[0].(map[string]any)["members"].([]any)
		fields := members[0].(map[string]any)["fields"].(map[string]any)
		fields["deferral"] = nil
	})
	_, err = Parse(requirementPayload)
	if ErrorCode(err) != "missing_deferral" {
		t.Fatalf("requirement semantic error = %v", err)
	}
	requirementDiagnostic := err.(*Error).Diagnostic()
	if strings.Contains(requirementDiagnostic.Path, "REQ-") || requirementDiagnostic.Path != "/groups/0/members/0/fields/deferral" {
		t.Fatalf("requirement diagnostic path = %q", requirementDiagnostic.Path)
	}

	profilePayload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		profiles := root["profiles"].([]any)
		copyValue := map[string]any{}
		for key, value := range profiles[0].(map[string]any) {
			copyValue[key] = value
		}
		copyValue["profileId"] = "RPROF-CODEC-UNUSED"
		root["profiles"] = append(profiles, copyValue)
	})
	_, err = Parse(profilePayload)
	assertDiagnostic(t, err, "vacuous_profile", "/profiles/1")
	if strings.Contains(err.Error(), "RPROF-CODEC-UNUSED") {
		t.Fatalf("profile diagnostic disclosed caller identity: %v", err)
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	for _, payload := range [][]byte{
		{},
		[]byte(`{"schemaVersion":2`),
		[]byte(`[]`),
		append(mustPayload(t), 0),
	} {
		_, err := Parse(payload)
		if err == nil {
			t.Fatalf("Parse(%q) unexpectedly passed", payload)
		}
	}
}

func TestParseAcceptsValidUnicodeSurrogatePairLosslessly(t *testing.T) {
	draft := testDraft()
	draft.NonClaimDefinitions[0].Statement = "The codec preserves \U0001f642 text."
	canonical := mustFormatDraft(t, draft)
	escaped := bytes.Replace(canonical, []byte("\U0001f642"), []byte(`\ud83d\ude42`), 1)
	result, err := Parse(escaped)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	expected, err := requirementsourcemodel.Normalize(draft)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if !projectionsEqual(result.Model, expected) {
		t.Fatal("valid surrogate pair changed semantic value")
	}
}

func TestFormatRejectsZeroModel(t *testing.T) {
	_, err := Format(requirementsourcemodel.Model{})
	if ErrorCode(err) != "invalid_model" {
		t.Fatalf("Format(zero) error = %v", err)
	}
}

func mustPayload(t *testing.T) []byte {
	t.Helper()
	payload, err := Format(mustModel(t))
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	return payload
}

func mutateRoot(t *testing.T, payload []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	mutate(root)
	result, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("marshal mutant: %v", err)
	}
	return result
}

func duplicateRootField(t *testing.T, payload []byte, field string) []byte {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	value, err := json.Marshal(root[field])
	if err != nil {
		t.Fatalf("marshal field: %v", err)
	}
	prefix := []byte("{")
	duplicate := append([]byte(`{"`+field+`":`), value...)
	duplicate = append(duplicate, ',')
	if !bytes.HasPrefix(payload, prefix) {
		t.Fatal("fixture is not a JSON object")
	}
	return append(duplicate, payload[1:]...)
}

func assertDiagnostic(t *testing.T, err error, code string, path string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s at %s", code, path)
	}
	if ErrorCode(err) != code {
		t.Fatalf("ErrorCode() = %q, want %q; error = %v", ErrorCode(err), code, err)
	}
	typed, ok := err.(*Error)
	if !ok {
		t.Fatalf("error type = %T", err)
	}
	if diagnostic := typed.Diagnostic(); diagnostic.Path != path {
		t.Fatalf("Diagnostic().Path = %q, want %q", diagnostic.Path, path)
	}
}
