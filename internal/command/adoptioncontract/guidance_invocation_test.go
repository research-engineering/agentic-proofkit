package adoptioncontract

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestGuidanceInvocationRendererSurvivesAggregateAndWireOverrides(t *testing.T) {
	for _, profile := range []struct {
		name, executable string
		prefix           []string
	}{
		{cliexec.ProfilePath, "", []string{"agentic-proofkit"}},
		{cliexec.ProfileNPMOffline, "", []string{"npm", "exec", "--offline", "--", "agentic-proofkit"}},
		{cliexec.ProfilePythonModule, "/opt/venv/bin/python", []string{"/opt/venv/bin/python", "-m", "agentic_proofkit"}},
		{cliexec.ProfilePythonModule, "/opt/task-validation/bin/python", []string{"/opt/task-validation/bin/python", "-m", "agentic_proofkit"}},
	} {
		renderer, err := cliexec.AdmitLauncherProfile(profile.name, profile.executable)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateOptions(Options{Mode: "bootstrap", Guidance: gradualadoption.GuidanceOptions{Renderer: renderer}}); err != nil {
			t.Fatal("renderer execution context became a guidance override")
		}
		for mask := 0; mask < 8; mask++ {
			for _, envelope := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%d/%t", profile.name, profile.executable, mask, envelope), func(t *testing.T) {
					input := validAggregateEnvelope()
					gradual := input["gradual"].(map[string]any)
					guidance := gradual["guidance"].(map[string]any)
					guidance["defaultMode"] = "warn"
					guidance["scopeEvidence"] = map[string]any{"checkedScope": "all", "touchedRuleIds": []any{"proofkit.test.rule"}}
					guidance["agentGuidance"].(map[string]any)["commands"] = []any{"go test ./..."}
					guidance["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{"witness-plan": "inputs/witness file.json "}
					options := Options{Mode: "guidance", AgentEnvelope: envelope}
					wantMode, wantScope := "warn", "all"
					wantTouched := []any{"proofkit.test.rule"}
					if mask&1 != 0 {
						options.Guidance.GuidanceMode, wantMode = "observe", "observe"
					}
					if mask&2 != 0 {
						options.Guidance.CheckedScope, wantScope = "touched", "touched"
					}
					if mask&4 != 0 {
						options.Guidance.TouchedRuleIDs, wantTouched = []string{"proofkit.other.rule"}, []any{"proofkit.other.rule"}
					}
					wire := aggregateInvocationJSON(t, testGuidanceEnvelope(input))
					decoded := aggregateInvocationJSON(t, input)
					output, code, err := BuildWithRenderer(decoded, options, renderer)
					if err != nil || code != 0 {
						t.Fatalf("aggregate exit=%d err=%v", code, err)
					}
					childOptions := options.Guidance
					childOptions.Renderer = renderer
					var child map[string]any
					if envelope {
						child, code, err = gradualadoption.BuildGuidanceEnvelopeFromContractEnvelope(wire, childOptions)
					} else {
						child, code, err = gradualadoption.BuildGuidanceFromContractEnvelope(wire, childOptions)
					}
					if err != nil || code != 0 || !reflect.DeepEqual(output, child) {
						t.Fatalf("aggregate delegation drifted: exit=%d err=%v", code, err)
					}
					wantArgv := append(append([]string{}, profile.prefix...), "witness-plan", "--input", "inputs/witness file.json ")
					if envelope {
						found := 0
						for _, raw := range child["commands"].([]any) {
							command := raw.(map[string]any)
							if argv, typed := command["argv"]; typed {
								found++
								actual := []string{}
								for _, raw := range argv.([]any) {
									actual = append(actual, raw.(string))
								}
								if !reflect.DeepEqual(actual, wantArgv) {
									t.Fatalf("current invocation renderer was lost: %#v", actual)
								}
							}
						}
						if found != 1 {
							t.Fatalf("typed generated commands=%d want 1", found)
						}
					} else {
						projected := child["diagnostics"].([]any)[0].(map[string]any)["value"].(map[string]any)
						if !reflect.DeepEqual(projected["commands"], []any{"go test ./...", cliexec.DisplayArgv(wantArgv)}) ||
							projected["guidanceMode"] != wantMode || projected["checkedScope"] != wantScope || !reflect.DeepEqual(projected["touchedRuleIds"], wantTouched) {
							t.Fatal("renderer or applied wire overrides were lost")
						}
					}
				})
			}
		}
	}
}

func TestAggregateBootstrapGuidanceSourceIsPortable(t *testing.T) {
	var source []byte
	for _, profile := range []struct{ name, python string }{
		{cliexec.ProfilePath, ""}, {cliexec.ProfileNPMOffline, ""},
		{cliexec.ProfilePythonModule, "/opt/venv/bin/python"},
		{cliexec.ProfilePythonModule, "/opt/task-validation/bin/python"},
	} {
		renderer, err := cliexec.AdmitLauncherProfile(profile.name, profile.python)
		if err != nil {
			t.Fatal(err)
		}
		output, code, err := BuildWithRenderer(aggregateInvocationJSON(t, validAggregateEnvelope()), Options{Mode: "bootstrap"}, renderer)
		if err != nil || code != 0 {
			t.Fatalf("aggregate bootstrap exit=%d err=%v", code, err)
		}
		payload := output.(map[string]any)["payloads"].(map[string]any)["adoptionGuidance"]
		encoded, err := stablejson.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if source == nil {
			source = encoded
		} else if !bytes.Equal(source, encoded) {
			t.Fatal("aggregate bootstrap persisted invocation context")
		}
		if _, code, err := gradualadoption.BuildGuidance(aggregateInvocationJSON(t, payload), gradualadoption.GuidanceOptions{Renderer: renderer}); err != nil || code != 0 {
			t.Fatalf("aggregate saved JSON failed public guidance admission: exit=%d err=%v", code, err)
		}
	}
}

func aggregateInvocationJSON(t *testing.T, input any) any {
	t.Helper()
	encoded, err := stablejson.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
