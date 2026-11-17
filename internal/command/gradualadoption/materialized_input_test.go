package gradualadoption

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/witnessplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func TestBootstrapPreparedInputPathsDistinguishStdin(t *testing.T) {
	for _, field := range []string{"adoptionGuidancePath", "adoptionProfilePath", "witnessPlanInputPath"} {
		for _, path := range []string{"-", "inputs/-.json", "inputs/-", "input-with-hyphens.json", " - "} {
			t.Run(field+"/"+path, func(t *testing.T) {
				input := validBootstrapInput()
				input["paths"].(map[string]any)[field] = path
				wrapped := bootstrapContractInput(input)
				refused := path == "-"
				for _, carrier := range []struct {
					input  any
					schema map[string]any
					builds []func(any) (map[string]any, int, error)
				}{
					{input, BootstrapInputStructure(), []func(any) (map[string]any, int, error){BuildBootstrap, BuildBootstrapMaterializationManifest, BuildBootstrapEnvelope}},
					{wrapped, BootstrapContractInputStructure(), []func(any) (map[string]any, int, error){BuildBootstrapFromContractEnvelope, BuildBootstrapMaterializationManifestFromContractEnvelope, BuildBootstrapEnvelopeFromContractEnvelope}},
				} {
					if err := schemacheck.Validate(carrier.schema, carrier.input); (err != nil) != refused {
						t.Fatalf("prepared path structure disagrees: refused=%t err=%v", refused, err)
					}
					for index, build := range carrier.builds {
						output, code, err := build(carrier.input)
						if !refused {
							if err != nil || code != 0 {
								t.Fatalf("ordinary prepared path refused: exit=%d err=%v", code, err)
							}
							continue
						}
						if code != 1 {
							t.Fatalf("prepared stdin accepted: exit=%d err=%v", code, err)
						}
						if index == 2 {
							source, _ := output["sourceReport"].(map[string]any)
							if err != nil || source["reportId"] != "proofkit.agent-envelope.invalid-input" || source["state"] != "failed" {
								t.Fatal("prepared stdin must produce only the invalid-input repair envelope")
							}
						} else if err == nil || output != nil || !strings.Contains(err.Error(), "materialized file, not stdin") {
							t.Fatalf("prepared stdin did not refuse before payloads: %v", err)
						}
					}
				}
			})
		}
	}
}

func TestBootstrapPreparedPathStructuresPublishExactExclusion(t *testing.T) {
	for _, schema := range []map[string]any{BootstrapInputStructure(), BootstrapContractInputStructure()} {
		properties := schema["properties"].(map[string]any)
		if bootstrap, ok := properties["bootstrap"].(map[string]any); ok {
			properties = bootstrap["properties"].(map[string]any)
		}
		paths := properties["paths"].(map[string]any)
		fields := paths["properties"].(map[string]any)
		if len(fields) != 3 {
			t.Fatal("prepared path structure narrowed unrelated targets")
		}
		for _, field := range []string{"adoptionGuidancePath", "adoptionProfilePath", "witnessPlanInputPath"} {
			if !reflect.DeepEqual(fields[field], map[string]any{"not": map[string]any{"const": "-"}}) {
				t.Fatalf("%s must exclude only the exact stdin sentinel at structural admission", field)
			}
		}
		if _, required := paths["required"]; required {
			t.Fatal("failure-collecting path members became required")
		}
	}
	for _, value := range []any{nil, false, "-", []any{}, map[string]any{}, map[string]any{"witnessPlanInputPath": false}, map[string]any{"witnessPlanInputPath": "../outside"}} {
		input := validBootstrapInput()
		input["paths"] = value
		result, err := BuildBootstrapResult(input)
		if err != nil || result.Record.State != "failed" {
			t.Fatalf("collected path failure changed phase: %v", err)
		}
		if err := schemacheck.Validate(BootstrapInputStructure(), input); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBootstrapPreparedInputsRoundTripThroughChildren(t *testing.T) {
	input := validBootstrapInput()
	paths := input["paths"].(map[string]any)
	paths["adoptionProfilePath"] = "inputs/adoption profile-.json"
	paths["adoptionGuidancePath"] = "inputs/adoption guidance-.json"
	paths["witnessPlanInputPath"] = "inputs/witness plan-.json"
	manifest, code, err := BuildBootstrapMaterializationManifest(input)
	if err != nil || code != 0 {
		t.Fatalf("bootstrap control: exit=%d err=%v", code, err)
	}
	matched := 0
	for _, raw := range manifest["files"].([]any) {
		file := raw.(map[string]any)
		var field, route string
		switch file["payloadKey"] {
		case "adoptionProfile":
			field, route = "adoptionProfilePath", "gradual-adoption"
		case "adoptionGuidance":
			field, route = "adoptionGuidancePath", "gradual-adoption-guidance"
		case "witnessPlanInput":
			field, route = "witnessPlanInputPath", "witness-plan"
		default:
			continue
		}
		if file["path"] != paths[field] {
			t.Fatalf("%s payload path changed", field)
		}
		if !containsString(anyStrings(manifest["nextCommands"]), cliexec.PathRenderer().DisplayCommand(route, "--input", paths[field].(string))) {
			t.Fatalf("%s command does not name its prepared file", route)
		}
		content := file["content"].(string)
		payload, err := admission.DecodeJSON(strings.NewReader(content), int64(len(content)))
		if err != nil {
			t.Fatal(err)
		}
		code = 0
		switch route {
		case "gradual-adoption":
			_, code, err = Build(payload)
		case "gradual-adoption-guidance":
			_, code, err = BuildGuidance(payload, GuidanceOptions{})
		case "witness-plan":
			_, err = witnessplan.Build(payload)
		}
		if err != nil || code != 0 {
			t.Fatalf("%s refused its prepared payload: exit=%d err=%v", route, code, err)
		}
		matched++
	}
	if matched != 3 {
		t.Fatalf("exercised %d prepared inputs, want 3", matched)
	}
}

func TestBootstrapPreservesNonInputDashTargetsAndCallerStdinCommands(t *testing.T) {
	for _, field := range []string{"adoptionReportArtifactPath", "guidanceReportArtifactPath", "module.specPath", "proofBindingPath", "repository.profilePath"} {
		input := validBootstrapInput()
		switch field {
		case "module.specPath":
			input["module"].(map[string]any)["specPath"] = "-"
		case "repository.profilePath":
			input["repository"].(map[string]any)["profilePath"] = "-"
		case "proofBindingPath":
			input[field] = "-"
		default:
			input["paths"].(map[string]any)[field] = "-"
		}
		callerCommand := "agentic-proofkit gradual-adoption --input -"
		input["commands"] = []any{callerCommand}
		result, err := BuildBootstrapResult(input)
		if err != nil || result.ExitCode != 0 {
			t.Fatalf("%s non-input target refused: exit=%d err=%v", field, result.ExitCode, err)
		}
		guidance := result.Payloads["adoptionGuidance"].(map[string]any)["agentGuidance"].(map[string]any)
		if guidance["commands"].([]any)[0] != callerCommand {
			t.Fatal("caller-owned stdin command was altered")
		}
		if err := schemacheck.Validate(BootstrapInputStructure(), input); err != nil {
			t.Fatal(err)
		}
	}
}

func bootstrapContractInput(input map[string]any) map[string]any {
	return map[string]any{
		"schema": "proofkit.gradual-adoption-profile.v1",
		"input": map[string]any{
			"budget": input["budget"], "module": input["module"], "nativeWitnesses": input["nativeWitnesses"],
			"packageVersionRef": input["packageVersionRef"], "repository": input["repository"], "rollback": input["rollback"],
			"proofBinding": map[string]any{"bindingPath": input["proofBindingPath"]},
		},
		"bootstrap": map[string]any{
			"bootstrapId": input["bootstrapId"], "commands": input["commands"], "defaultMode": input["guidanceMode"],
			"nonClaims": input["nonClaims"], "paths": input["paths"],
			"scopeEvidence": map[string]any{"checkedScope": input["checkedScope"], "touchedRuleIds": input["touchedRuleIds"]},
		},
		"guidance": map[string]any{"ownerRoute": input["ownerRoute"]},
	}
}
