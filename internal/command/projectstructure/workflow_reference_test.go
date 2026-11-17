package projectstructure

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionworkflow"
	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestScaffoldWorkflowCommandsResolveExactChildMaterializedPaths(t *testing.T) {
	for _, suffix := range []string{"", " ", "  "} {
		for _, field := range []string{"adoptionGuidancePath", "witnessPlanInputPath", "both"} {
			t.Run(field+"/suffix="+suffix, func(t *testing.T) {
				input := validProjectStructureInput()
				paths := input["bootstrap"].(map[string]any)["paths"].(map[string]any)
				if field == "both" || field == "adoptionGuidancePath" {
					paths["adoptionGuidancePath"] = "inputs/guidance file.json" + suffix
				}
				if field == "both" || field == "witnessPlanInputPath" {
					paths["witnessPlanInputPath"] = "inputs/witness file.json" + suffix
				}
				result, err := BuildResult(input)
				if err != nil || result.ExitCode != 0 || result.Record.State != "passed" {
					t.Fatalf("exact paths refused: exit=%d err=%v", result.ExitCode, err)
				}
				childManifest, err := gradualadoption.BootstrapMaterializationManifest(result.Bootstrap)
				if err != nil {
					t.Fatal(err)
				}
				materializedInputs := map[string]any{}
				for _, raw := range result.Manifest["files"].([]any) {
					file := raw.(map[string]any)
					if file["materializationStatus"] != "payload_available" {
						continue
					}
					content := file["content"].(string)
					payload, err := admission.DecodeJSON(strings.NewReader(content), int64(len(content)))
					if err != nil {
						t.Fatal(err)
					}
					materializedInputs[file["path"].(string)] = payload
				}
				projectPaths := input["paths"].(map[string]any)
				rebuiltBootstrap, err := gradualadoption.BuildBootstrapResult(materializedInputs[projectPaths["bootstrapInputPath"].(string)])
				if err != nil || rebuiltBootstrap.ExitCode != 0 {
					t.Fatalf("materialized bootstrap refused: exit=%d err=%v", rebuiltBootstrap.ExitCode, err)
				}
				rebuiltManifest, err := gradualadoption.BootstrapMaterializationManifest(rebuiltBootstrap)
				if err != nil || !reflect.DeepEqual(rebuiltManifest, childManifest) {
					t.Fatal("materialized bootstrap changed its child manifest")
				}
				workflowPayload := materializedInputs[projectPaths["workflowInputPath"].(string)]
				if !reflect.DeepEqual(workflowPayload, result.AdoptionWorkflowInput) {
					t.Fatal("parent manifest changed its workflow input")
				}
				rebuiltWorkflow, err := adoptionworkflow.BuildResult(workflowPayload)
				if err != nil || rebuiltWorkflow.ExitCode != 0 || !reflect.DeepEqual(rebuiltWorkflow.Plan, result.AdoptionWorkflowPlan) {
					t.Fatalf("materialized workflow changed its plan: exit=%d err=%v", rebuiltWorkflow.ExitCode, err)
				}
				for _, item := range []struct{ field, payload, kind, route string }{
					{"adoptionGuidancePath", "adoptionGuidance", "gradual_adoption_guidance", "gradual-adoption-guidance"},
					{"witnessPlanInputPath", "witnessPlanInput", "bootstrap_witness_plan", "witness-plan"},
				} {
					wantPath := paths[item.field].(string)
					var child map[string]any
					for _, raw := range childManifest["files"].([]any) {
						file := raw.(map[string]any)
						if file["payloadKey"] == item.payload {
							if child != nil {
								t.Fatal("duplicate child payload")
							}
							child = file
						}
					}
					if child == nil || child["path"] != wantPath {
						t.Fatalf("%s child path=%v, want %q", item.payload, child, wantPath)
					}
					parentMatches := 0
					for _, raw := range result.Manifest["files"].([]any) {
						file := raw.(map[string]any)
						if file["path"] == wantPath {
							parentMatches++
							for _, key := range []string{"content", "contentKind", "contentSha256", "materializationStatus"} {
								if file[key] != child[key] {
									t.Fatalf("%s parent changed child %s", item.payload, key)
								}
							}
						}
					}
					if parentMatches != 1 {
						t.Fatalf("parent file count at %q=%d, want 1", wantPath, parentMatches)
					}
					refs := 0
					for _, raw := range result.AdoptionWorkflowInput["inputRefs"].([]any) {
						ref := raw.(map[string]any)
						if ref["inputKind"] == item.kind {
							refs++
							if ref["path"] != wantPath {
								t.Fatalf("%s workflow ref=%q, want exact child path %q", item.kind, ref["path"], wantPath)
							}
						}
					}
					commands := 0
					for _, rawPhase := range rebuiltWorkflow.Plan["phases"].([]any) {
						for _, raw := range rawPhase.(map[string]any)["commands"].([]any) {
							command := raw.(map[string]any)
							if command["commandId"] == "proofkit.adoption-workflow.command."+item.route {
								commands++
								if !reflect.DeepEqual(command["argv"], []any{"agentic-proofkit", item.route, "--input", wantPath}) ||
									!reflect.DeepEqual(command["inputRefIds"], []any{item.kind}) {
									t.Fatalf("%s command lost exact ref/argv identity: %#v", item.route, command)
								}
							}
						}
					}
					if refs != 1 || commands != 1 {
						t.Fatalf("%s refs=%d commands=%d, want 1 each", item.route, refs, commands)
					}
					wantCommand := cliexec.PathRenderer().DisplayCommand(item.route, "--input", wantPath)
					for _, manifest := range []map[string]any{childManifest, result.Manifest} {
						if !slices.Contains(manifest["nextCommands"].([]any), any(wantCommand)) {
							t.Fatalf("%s next command does not name the materialized file", item.route)
						}
					}
					content := child["content"].(string)
					payload, err := admission.DecodeJSON(strings.NewReader(content), int64(len(content)))
					if err != nil {
						t.Fatal(err)
					}
					code := 0
					if item.route == "witness-plan" {
						_, err = witnessplan.Build(payload)
					} else {
						_, code, err = gradualadoption.BuildGuidance(payload, gradualadoption.GuidanceOptions{})
					}
					if err != nil || code != 0 {
						t.Fatalf("%s materialized payload refused: exit=%d err=%v", item.route, code, err)
					}
				}
			})
		}
	}
}

func TestScaffoldRefusesConflictingBootstrapPayloadPaths(t *testing.T) {
	input := validProjectStructureInput()
	paths := input["bootstrap"].(map[string]any)["paths"].(map[string]any)
	paths["adoptionGuidancePath"] = paths["witnessPlanInputPath"]
	for _, build := range []func(any) (map[string]any, int, error){Build, BuildEnvelope} {
		output, code, err := build(input)
		if output != nil || code != 1 || err == nil || !strings.Contains(err.Error(), "file paths must be sorted and unique") {
			t.Fatalf("parent uniqueness refusal changed phase: exit=%d err=%v", code, err)
		}
	}
}
