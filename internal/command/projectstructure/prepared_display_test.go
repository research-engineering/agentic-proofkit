package projectstructure

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionworkflow"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestScaffoldOwnPreparedDisplaysMatchTheEnvelopeBoundary(t *testing.T) {
	for _, key := range []string{"repoProfileScaffoldInputPath", "bootstrapInputPath", "workflowInputPath"} {
		for _, path := range []string{"inputs/a b/authorization:", "inputs/unsafe\u202e.json"} {
			for _, build := range []func(any) (map[string]any, int, error){Build, BuildEnvelope} {
				input := validProjectStructureInput()
				input["paths"].(map[string]any)[key] = path
				output, exit, err := build(input)
				if err == nil || output != nil || exit != 1 || strings.Contains(err.Error(), path) {
					t.Fatal("unsafe own display escaped as a passed or partially executable result")
				}
			}
		}
	}
	for _, path := range []string{"inputs/a b.json", "inputs/a'b.json "} {
		input := validProjectStructureInput()
		input["paths"].(map[string]any)["workflowInputPath"] = path
		renderer, err := cliexec.AdmitLauncherProfile(cliexec.ProfilePythonModule, "/opt/task-validation/bin/python")
		if err != nil {
			t.Fatal(err)
		}
		result, err := BuildResultWithRenderer(input, renderer)
		if err != nil || result.ExitCode != 0 || len(result.commands) != 6 {
			t.Fatal("legal quoted root input lost its prepared command")
		}
		want := renderer.Argv("adoption-workflow-plan", "--input", strings.TrimSpace(path))
		if !reflect.DeepEqual(result.commands[2].argv, want) || result.Manifest["nextCommands"].([]any)[2] != cliexec.DisplayArgv(want) {
			t.Fatal("root-owned normalization or display diverged from canonical argv")
		}
	}
}

func TestScaffoldWorkflowCannotRecreateRefusedChildOperations(t *testing.T) {
	for _, key := range []string{"adoptionGuidancePath", "witnessPlanInputPath"} {
		input := validProjectStructureInput()
		unsafe := "inputs/unsafe\u202e.json"
		input["bootstrap"].(map[string]any)["paths"].(map[string]any)[key] = unsafe
		result, err := BuildResult(input)
		if err != nil || result.ExitCode != 1 || result.AdoptionWorkflowPlan["planState"] != "blocked" {
			t.Fatalf("refused child did not retain a collected, blocked parent result: %v", err)
		}
		for _, raw := range result.AdoptionWorkflowInput["inputRefs"].([]any) {
			if raw.(map[string]any)["path"] == unsafe {
				t.Fatal("unadmitted child route was reconstructed from file existence")
			}
		}
		replayed, exit, err := adoptionworkflow.Build(result.AdoptionWorkflowInput)
		if err != nil || exit != 1 || replayed["planState"] != "blocked" {
			t.Fatal("saved workflow input did not preserve the child's availability decision")
		}
		for _, phase := range replayed["phases"].([]any) {
			for _, raw := range phase.(map[string]any)["commands"].([]any) {
				for _, argument := range raw.(map[string]any)["argv"].([]any) {
					if argument == unsafe {
						t.Fatal("refused child operation reappeared as nested argv")
					}
				}
			}
		}
	}
}
