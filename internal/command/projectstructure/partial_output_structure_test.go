package projectstructure

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func TestScaffoldPartialPreparedCommandsMatchOutputStructure(t *testing.T) {
	fields := []string{"adoptionProfilePath", "adoptionGuidancePath", "witnessPlanInputPath"}
	operations := []string{"gradual-adoption", "gradual-adoption-guidance", "witness-plan"}
	for _, profile := range []struct{ name, python string }{
		{cliexec.ProfilePath, ""}, {cliexec.ProfileNPMOffline, ""},
		{cliexec.ProfilePythonModule, "/tmp/proofkit venv/bin/python"},
	} {
		renderer, err := cliexec.AdmitLauncherProfile(profile.name, profile.python)
		if err != nil {
			t.Fatal(err)
		}
		for mask := 0; mask < 8; mask++ {
			t.Run(fmt.Sprintf("%s/mask-%d", profile.name, mask), func(t *testing.T) {
				input := validProjectStructureInput()
				paths := input["paths"].(map[string]any)
				want := []any{
					renderer.DisplayCommand("scaffold-profile-plan", "--input", paths["repoProfileScaffoldInputPath"].(string)),
					renderer.DisplayCommand("gradual-adoption-bootstrap", "--input", paths["bootstrapInputPath"].(string)),
					renderer.DisplayCommand("adoption-workflow-plan", "--input", paths["workflowInputPath"].(string)),
				}
				childPaths := input["bootstrap"].(map[string]any)["paths"].(map[string]any)
				wantChild := []any{}
				for index, field := range fields {
					if mask&(1<<index) == 0 {
						childPaths[field] = fmt.Sprintf("proofkit/child-%d\u202e.json", index)
					} else {
						wantChild = append(wantChild, renderer.DisplayCommand(operations[index], "--input", childPaths[field].(string)))
					}
				}
				want = append(want, wantChild...)
				result, err := BuildResultWithRenderer(input, renderer)
				if err != nil {
					t.Fatalf("child command failure must remain collected: %v", err)
				}
				state, code := "failed", 1
				if mask == 7 {
					state, code = "passed", 0
				}
				if result.ExitCode != code || result.Record.State != state || result.Bootstrap.ExitCode != code || result.Bootstrap.Record.State != state {
					t.Fatalf("lost collected failure: scaffold=%s/%d bootstrap=%s/%d", result.Record.State, result.ExitCode, result.Bootstrap.Record.State, result.Bootstrap.ExitCode)
				}
				if !reflect.DeepEqual(result.Manifest["nextCommands"], want) || !reflect.DeepEqual(result.Bootstrap.JSONValue()["nextCommands"], wantChild) {
					t.Fatal("manifest must contain exactly the three own commands and available child commands, without placeholders")
				}
				refs := []any{}
				if mask&4 != 0 {
					refs = append(refs, "bootstrap_witness_plan")
				}
				refs = append(refs, "gradual_adoption_bootstrap")
				if mask&2 != 0 {
					refs = append(refs, "gradual_adoption_guidance")
				}
				refs = append(refs, "repo_profile_scaffold")
				for _, carrier := range []map[string]any{result.AdoptionWorkflowInput, result.AdoptionWorkflowPlan} {
					got := []any{}
					for _, raw := range carrier["inputRefs"].([]any) {
						got = append(got, raw.(map[string]any)["inputKind"])
					}
					if !reflect.DeepEqual(got, refs) {
						t.Fatalf("unavailable child operation retained a workflow ref: %v", got)
					}
				}
				if mask&6 != 6 && result.AdoptionWorkflowPlan["planState"] != "blocked" {
					t.Fatal("missing child operation must block the nested workflow")
				}
				if err := schemacheck.Validate(OutputStructure(), result.JSONValue()); err != nil {
					t.Fatalf("actual %d-command carrier refused: %v", len(want), err)
				}
				for _, raw := range result.Manifest["sourceReports"].([]any) {
					source := raw.(map[string]any)
					if source["reportKind"] == "proofkit.gradual-adoption-bootstrap" && source["state"] != state {
						t.Fatal("manifest source erased the child failure state")
					}
				}
			})
		}
	}
}

func TestScaffoldNextCommandsRejectOutsideReachableBounds(t *testing.T) {
	result, err := BuildResult(validProjectStructureInput())
	if err != nil {
		t.Fatal(err)
	}
	commands := result.Manifest["nextCommands"].([]any)
	for _, count := range []int{2, 7} {
		changed := make([]any, count)
		for index := range changed {
			changed[index] = commands[index%len(commands)]
		}
		result.Manifest["nextCommands"] = changed
		if outputMemberShapes()["materializationManifest"].CheckGenerated(result.Manifest, "manifest") == nil ||
			schemacheck.Validate(OutputStructure(), result.JSONValue()) == nil {
			t.Fatalf("accepted unreachable command count %d", count)
		}
	}
}
