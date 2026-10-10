package app

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
)

func TestBootstrapSafetySemanticCutoverKeepsWireVersions(t *testing.T) {
	commands, _, err := indexPublicABIRecords(readCLIContractRaw(t)["commands"], "command")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ command, identity, wire, root string }{
		{"gradual-adoption-bootstrap", "proofkit.gradual-adoption-bootstrap.input.v2", "1", "proofkit.gradual-adoption-bootstrap.input.v1.root-shape"},
		{"adoption-contract-envelope", "proofkit.adoption-contract-envelope.input.v3", "2", "proofkit.adoption-contract-envelope.input.v2.root-shape"},
		{"scaffold-project-structure", "proofkit.scaffold-project-structure.input.v2", "1", "proofkit.scaffold-project-structure.input.v1.root-shape"},
	} {
		input := commands[row.command]["inputContract"].(map[string]any)
		if input["contractId"] != row.identity || input["schemaVersion"] != json.Number(row.wire) || input["rootDefinitionRef"] != row.root {
			t.Fatal("bootstrap security cutover confused wire, semantic or structural identity")
		}
	}
}

func TestBootstrapSafetyCLIClosesEveryPublicEgress(t *testing.T) {
	for _, mode := range []string{"direct", "pointer", "contract", "aggregate", "scaffold"} {
		for _, outputFlag := range []string{"", "--agent-envelope", "--materialization-manifest"} {
			if mode == "scaffold" && outputFlag == "--materialization-manifest" {
				continue
			}
			t.Run(mode+"/"+outputFlag, func(t *testing.T) {
				aggregate := invocationProfileObject(t, invocationProfileJSON(t, cliAdoptionContractEnvelopeInput()))
				gradual := invocationProfileObjectValue(t, aggregate["gradual"], "gradual")
				bootstrap, err := gradualadoption.BootstrapInputFromContractEnvelope(gradual)
				if err != nil {
					t.Fatal(err)
				}
				var packet any = bootstrap
				budget := bootstrap["budget"].(map[string]any)
				args := []string{"gradual-adoption-bootstrap", "--input", "-"}
				switch mode {
				case "pointer":
					packet = map[string]any{"candidate": bootstrap}
					args = append(args, "--input-pointer", "/candidate")
				case "contract":
					packet = gradual
					budget = gradual["input"].(map[string]any)["budget"].(map[string]any)
					args = append(args, "--contract-envelope")
				case "aggregate":
					packet = aggregate
					budget = gradual["input"].(map[string]any)["budget"].(map[string]any)
					args = []string{"adoption-contract-envelope", "--input", "-", "--mode", "bootstrap"}
				case "scaffold":
					packet = invocationProfileProjectInput(bootstrap)
					args = []string{"scaffold-project-structure", "--input", "-"}
				}
				if outputFlag != "" {
					args = append(args, outputFlag)
				}
				var stdout, stderr bytes.Buffer
				if exit := Run(context.Background(), args, strings.NewReader(invocationProfileEncode(t, packet)), &stdout, &stderr); exit != 0 || stderr.Len() != 0 || stdout.Len() == 0 {
					t.Fatalf("positive control did not reach this public route: exit=%d", exit)
				}
				marker := "api_" + "key=synthetic-cli-bootstrap-fixture"
				for _, payload := range []any{map[string]any{"nested": marker}, map[string]any{"api_key": "synthetic-opaque-cli-value"}} {
					budget["unadmittedExtra"] = []any{payload}
					stdout.Reset()
					stderr.Reset()
					exit := Run(context.Background(), args, strings.NewReader(invocationProfileEncode(t, packet)), &stdout, &stderr)
					if exit != 1 || strings.Contains(stdout.String()+stderr.String(), marker) || strings.Contains(stdout.String()+stderr.String(), "synthetic-opaque-cli-value") {
						t.Fatal("unsafe public input was not refused without disclosure")
					}
					if outputFlag == "--agent-envelope" {
						value := invocationProfileObject(t, invocationProfileJSON(t, stdout.String()))
						source := invocationProfileObjectValue(t, value["sourceReport"], "sourceReport")
						if stderr.Len() != 0 || source["reportId"] != "proofkit.agent-envelope.invalid-input" || source["state"] != "failed" {
							t.Fatal("invalid-input envelope ABI drift")
						}
					} else if stdout.Len() != 0 || stderr.String() != "gradual adoption bootstrap input must not contain secret-shaped keys or values\n" {
						t.Fatal("ordinary refusal stream ABI drift")
					}
				}
			})
		}
	}
}

func TestGradualAdoptionFailedRollbackNondisclosureCLI(t *testing.T) {
	for _, field := range []string{"owner", "versionPin"} {
		for _, envelope := range []bool{false, true} {
			input := cliGradualAdoptionInput()
			marker := "api_" + "key=synthetic-failed-rollback-fixture"
			input["rollback"].(map[string]any)[field] = marker
			input["budget"].(map[string]any)["profileLines"] = json.Number("999999")
			var packet any = input
			args := []string{"gradual-adoption", "--input", "-"}
			if envelope {
				packet = map[string]any{"schema": "proofkit.gradual-adoption-profile.v1", "input": input}
				args = append(args, "--contract-envelope")
			}
			var stdout, stderr bytes.Buffer
			exit := Run(context.Background(), args, strings.NewReader(invocationProfileEncode(t, packet)), &stdout, &stderr)
			if exit != 1 || stderr.Len() != 0 {
				t.Fatal("failed-report control did not reach ordinary policy failure")
			}
			value := invocationProfileObject(t, invocationProfileJSON(t, stdout.String()))
			if value["state"] != "failed" || value["reportKind"] != "proofkit.gradual-adoption" {
				t.Fatal("failed report identity/state drift")
			}
			if strings.Contains(stdout.String()+stderr.String(), marker) {
				t.Fatal("failed adoption report disclosed rollback identity")
			}
		}
	}
}

func TestGradualAdoptionOptionalRollbackConservationCLI(t *testing.T) {
	values := []struct {
		name    string
		present bool
		value   any
	}{
		{"absent", false, nil},
		{"null", true, nil},
		{"number", true, json.Number("42")},
		{"boolean", true, false},
		{"array", true, []any{"benign"}},
		{"object", true, map[string]any{"benign": true}},
	}
	for _, field := range []string{"owner", "versionPin"} {
		for _, state := range []struct {
			name string
			exit int
		}{{"passed", 0}, {"failed", 1}} {
			for _, route := range []struct {
				name     string
				envelope bool
			}{{"direct", false}, {"contract-envelope", true}} {
				t.Run(field+"/"+state.name+"/"+route.name, func(t *testing.T) {
					run := func(t *testing.T, present bool, value any) string {
						t.Helper()
						input := cliGradualAdoptionInput()
						rollback := input["rollback"].(map[string]any)
						if present {
							rollback[field] = value
						} else {
							delete(rollback, field)
						}
						if state.exit == 1 {
							input["budget"].(map[string]any)["profileLines"] = json.Number("999999")
						}
						var packet any = input
						args := []string{"gradual-adoption", "--input", "-"}
						if route.envelope {
							packet = map[string]any{"schema": "proofkit.gradual-adoption-profile.v1", "input": input}
							args = append(args, "--contract-envelope")
						}
						var stdout, stderr bytes.Buffer
						exit := Run(context.Background(), args, strings.NewReader(invocationProfileEncode(t, packet)), &stdout, &stderr)
						if exit != state.exit || stderr.Len() != 0 {
							t.Fatalf("optional rollback changed report outcome: exit=%d", exit)
						}
						record := invocationProfileObject(t, invocationProfileJSON(t, stdout.String()))
						if record["state"] != state.name || record["reportKind"] != "proofkit.gradual-adoption" || record["reportId"] != input["adoptionId"] {
							t.Fatal("optional rollback changed report identity or state")
						}
						return stdout.String()
					}
					baseline := run(t, true, "")
					for _, value := range values {
						t.Run(value.name, func(t *testing.T) {
							if run(t, value.present, value.value) != baseline {
								t.Fatal("optional rollback must preserve the complete empty-string report")
							}
						})
					}
				})
			}
		}
	}
}
