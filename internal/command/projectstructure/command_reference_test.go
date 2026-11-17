package projectstructure

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestScaffoldPreparedCommandsPreserveManifestContextAndActualRenderer(t *testing.T) {
	for _, profile := range []struct{ name, python string }{
		{cliexec.ProfilePath, ""}, {cliexec.ProfileNPMOffline, ""},
		{cliexec.ProfilePythonModule, "/opt/task-validation/bin/python"},
	} {
		t.Run(profile.name, func(t *testing.T) {
			renderer, err := cliexec.AdmitLauncherProfile(profile.name, profile.python)
			if err != nil {
				t.Fatal(err)
			}
			input := validProjectStructureInput()
			prefix := "inputs/fixtures/" + strings.Repeat("a", 500) + "/"
			paths := input["paths"].(map[string]any)
			for _, key := range []string{"repoProfileScaffoldInputPath", "bootstrapInputPath", "workflowInputPath"} {
				paths[key] = prefix + key + " file.json "
			}
			childPaths := input["bootstrap"].(map[string]any)["paths"].(map[string]any)
			for _, key := range []string{"adoptionProfilePath", "adoptionGuidancePath", "witnessPlanInputPath"} {
				childPaths[key] = prefix + key + " file.json "
			}
			result, err := BuildResultWithRenderer(input, renderer)
			if err != nil || result.ExitCode != 0 {
				t.Fatalf("legal exact paths failed: exit=%d err=%v", result.ExitCode, err)
			}
			envelope, code, err := BuildEnvelopeFromResult(result)
			if err != nil || code != 0 {
				t.Fatalf("envelope failed: exit=%d err=%v", code, err)
			}
			contexts := map[string]any{}
			for _, raw := range envelope["contextRefs"].([]any) {
				context := raw.(map[string]any)
				contexts[context["refId"].(string)] = context["ref"]
			}
			commands := envelope["commands"].([]any)
			if len(commands) != 6 {
				t.Fatalf("retained %d commands, want all six", len(commands))
			}
			for index, raw := range commands {
				command := raw.(map[string]any)
				argv := command["argv"].([]any)
				want := result.commands[index].argv
				if !reflect.DeepEqual(argv, admit.StringSliceToAny(want)) {
					t.Fatalf("command %d diverged from canonical argv", index)
				}
				if cliexec.DisplayArgv(want) != result.Manifest["nextCommands"].([]any)[index] {
					t.Fatalf("manifest command %d diverged from canonical invocation", index)
				}
				path := argv[len(argv)-1]
				found := 0
				for _, value := range contexts {
					if value == path {
						found++
					}
				}
				if found != 1 {
					t.Fatalf("command %d has %d exact materialized contexts", index, found)
				}
			}
			// Removing one materialization target cannot retain its executable route.
			files := result.Manifest["files"].([]any)
			target := result.commands[0].inputRef
			retained := []any{}
			for _, raw := range files {
				if raw.(map[string]any)["path"] != target {
					retained = append(retained, raw)
				}
			}
			result.Manifest["files"] = retained
			degraded, _, err := BuildEnvelopeFromResult(result)
			if err != nil {
				t.Fatal(err)
			}
			for _, raw := range degraded["commands"].([]any) {
				if raw.(map[string]any)["commandId"] == "proofkit.project-structure.command.001" {
					t.Fatal("command survived loss of its materialized context")
				}
			}
		})
	}
}
