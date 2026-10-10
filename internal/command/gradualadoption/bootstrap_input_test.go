package gradualadoption

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestBootstrapRejectsSecretPayloadsInEveryOutputMode(t *testing.T) {
	builders := []struct {
		name  string
		build func(any) (map[string]any, int, error)
	}{
		{"json", BuildBootstrap},
		{"manifest", BuildBootstrapMaterializationManifest},
		{"envelope", BuildBootstrapEnvelope},
	}
	for _, fixture := range admit.ReportVisibleRedactionFixtures() {
		for _, field := range []string{"budget", "repository", "rollback", "nativeWitnesses"} {
			for _, builder := range builders {
				t.Run(fixture.Name+"/"+field+"/"+builder.name, func(t *testing.T) {
					input := validBootstrapInput()
					input[field].(map[string]any)["unadmittedExtra"] = []any{map[string]any{"nested": fixture.Input}}
					output, exit, err := builder.build(input)
					if exit != 1 {
						t.Fatalf("unsafe payload was not refused: exit=%d err=%v", exit, err)
					}
					if builder.name == "envelope" {
						source, ok := output["sourceReport"].(map[string]any)
						if err != nil || !ok || source["reportId"] != "proofkit.agent-envelope.invalid-input" || source["state"] != "failed" {
							t.Fatal("unsafe payload must return the invalid-input repair envelope")
						}
					} else if output != nil || err == nil {
						t.Fatal("unsafe payload must refuse before ordinary or manifest output")
					}
					assertNoBootstrapDisclosure(t, output, err, fixture.SensitiveNeedles)
				})
			}
		}
	}
	input := validBootstrapInput()
	marker := "api_" + "key=synthetic-key-fixture"
	input["budget"].(map[string]any)[marker] = "benign"
	if output, exit, err := BuildBootstrap(input); output != nil || exit != 1 || err == nil || strings.Contains(err.Error(), marker) {
		t.Fatal("unsafe object key was not refused without disclosure")
	}
}

func TestBootstrapUsesAdmittedProfilePathWithoutPanic(t *testing.T) {
	for _, value := range []any{nil, json.Number("42"), "../outside.json", "api_" + "key=synthetic-path-fixture"} {
		input := validBootstrapInput()
		input["repository"].(map[string]any)["profilePath"] = value
		result, err := BuildBootstrapResult(input)
		if err != nil {
			if _, secret := value.(string); secret && admit.ContainsSecretLikeValue(value.(string)) {
				continue
			}
			t.Fatal(err)
		}
		if result.ExitCode != 1 || result.Record.State != "failed" {
			t.Fatal("invalid profile path did not produce a failed report")
		}
		found := false
		for _, raw := range result.PlannedFiles {
			file := raw.(map[string]any)
			if file["purpose"] == "caller-owned proofkit profile" {
				found = true
				if file["path"] != "" {
					t.Fatal("planned profile retained an unadmitted path")
				}
			}
		}
		if !found {
			t.Fatal("planned profile obligation was not exercised")
		}
	}
	input := validBootstrapInput()
	delete(input["repository"].(map[string]any), "profilePath")
	if result, err := BuildBootstrapResult(input); err != nil || result.Record.State != "failed" {
		t.Fatal("absent profile path must fail without panic")
	}
}

func TestBootstrapRejectsStructuredCredentialPairs(t *testing.T) {
	for _, key := range []string{"api_key", "access-token", "Authorization", "password", "token"} {
		for _, build := range []func(any) (map[string]any, int, error){BuildBootstrap, BuildBootstrapMaterializationManifest, BuildBootstrapEnvelope} {
			input := validBootstrapInput()
			marker := "synthetic-opaque-pair-fixture"
			input["budget"].(map[string]any)["unadmittedExtra"] = []any{map[string]any{key: marker}}
			output, exit, err := build(input)
			if exit != 1 {
				t.Fatal("credential-label/value composition was accepted")
			}
			if err == nil {
				source, ok := output["sourceReport"].(map[string]any)
				if !ok || source["reportId"] != "proofkit.agent-envelope.invalid-input" || source["state"] != "failed" {
					t.Fatal("pair did not refuse before payload emission")
				}
			} else if output != nil {
				t.Fatal("pair refusal emitted ordinary payload")
			}
			assertNoBootstrapDisclosure(t, output, err, []string{marker})
		}
	}
}

func TestBootstrapRejectsUnsafeJSONKeys(t *testing.T) {
	for _, key := range []string{"", "\x00", "line\nbreak"} {
		input := validBootstrapInput()
		input["budget"].(map[string]any)["unadmittedExtra"] = map[string]any{key: "benign"}
		if output, exit, err := BuildBootstrap(input); output != nil || exit != 1 || err == nil {
			t.Fatal("invalid JSON key must refuse before payload emission")
		}
	}
}

func TestBootstrapSnapshotRefusesUnsafeSerializationWithoutDisclosure(t *testing.T) {
	marker := "api_" + "key=synthetic-invalid-number"
	for _, value := range []any{json.Number(marker), string([]byte{0xff}), make(chan int)} {
		input := validBootstrapInput()
		input["budget"].(map[string]any)["unadmittedExtra"] = value
		output, exit, err := BuildBootstrap(input)
		if output != nil || exit != 1 || err == nil || err.Error() != "gradual adoption bootstrap input must be JSON-serializable" {
			t.Fatal("serialization refusal must use a fixed nondisclosing diagnostic")
		}
	}
}

func TestBootstrapOwnsDetachedPayloadsAndPreservesJSONNumbers(t *testing.T) {
	input := validBootstrapInput()
	input["budget"].(map[string]any)["unadmittedExtra"] = []any{map[string]any{"number": json.Number("1.2300e+4")}}
	result, err := BuildBootstrapResult(input)
	if err != nil || result.Record.State != "failed" {
		t.Fatalf("benign failed input was not retained: %v", err)
	}
	before, err := stablejson.Marshal(result.JSONValue())
	if err != nil {
		t.Fatal(err)
	}
	assertBootstrapNumberTypeAndToken(t, result.JSONValue())
	wire, err := admission.DecodeJSON(bytes.NewReader(before), int64(len(before)))
	if err != nil {
		t.Fatal(err)
	}
	assertBootstrapNumberTypeAndToken(t, wire.(map[string]any))
	manifestBefore, err := BootstrapMaterializationManifest(result)
	if err != nil {
		t.Fatal(err)
	}
	input["budget"].(map[string]any)["unadmittedExtra"].([]any)[0].(map[string]any)["number"] = json.Number("0")
	input["repository"].(map[string]any)["profilePath"] = "changed.json"
	input["nativeWitnesses"].(map[string]any)["commands"].([]any)[0].(map[string]any)["argv"].([]any)[0] = "changed"
	input["rollback"].(map[string]any)["owner"] = "changed"
	input["module"].(map[string]any)["requirementIds"].([]any)[0] = "REQ-CHANGED"
	after, err := stablejson.Marshal(result.JSONValue())
	if err != nil || string(before) != string(after) {
		t.Fatal("caller mutation changed result")
	}
	manifestAfter, err := BootstrapMaterializationManifest(result)
	if err != nil || !reflect.DeepEqual(manifestBefore, manifestAfter) {
		t.Fatal("caller mutation changed manifest")
	}
	profile := result.Payloads["adoptionProfile"].(map[string]any)
	profile["rollback"].(map[string]any)["owner"] = "result-only"
	if input["rollback"].(map[string]any)["owner"] != "changed" {
		t.Fatal("result mutation changed caller")
	}
}

func assertBootstrapNumberTypeAndToken(t *testing.T, output map[string]any) {
	t.Helper()
	profile := output["payloads"].(map[string]any)["adoptionProfile"].(map[string]any)
	extra := profile["budget"].(map[string]any)["unadmittedExtra"].([]any)[0].(map[string]any)
	number, ok := extra["number"].(json.Number)
	if !ok || number.String() != "1.2300e+4" {
		t.Fatal("forwarded value must retain JSON number type and token")
	}
}

func TestGradualAdoptionRedactsOptionalRollbackText(t *testing.T) {
	for _, fixture := range admit.ReportVisibleRedactionFixtures() {
		for _, field := range []string{"owner", "versionPin"} {
			input := validAdoptionInput()
			input["rollback"].(map[string]any)[field] = fixture.Input
			output, exit, err := Build(input)
			if err != nil || exit != 0 {
				t.Fatalf("optional text changed policy: %v", err)
			}
			assertNoBootstrapDisclosure(t, output, nil, fixture.SensitiveNeedles)
		}
	}
}

func assertNoBootstrapDisclosure(t *testing.T, output map[string]any, err error, needles []string) {
	t.Helper()
	raw, encodeErr := stablejson.Marshal(output)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	text := string(raw)
	if err != nil {
		text += err.Error()
	}
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			t.Fatal("report-visible disclosure")
		}
	}
}
