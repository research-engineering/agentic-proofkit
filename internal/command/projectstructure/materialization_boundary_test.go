package projectstructure

import (
	"bytes"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/witnessplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestScaffoldDoesNotReplaceAChildWitnessWithAProfileDraft(t *testing.T) {
	input := validProjectStructureInput()
	witnessPath := input["bootstrap"].(map[string]any)["paths"].(map[string]any)["witnessPlanInputPath"].(string)
	input["repoProfileScaffold"].(map[string]any)["repository"].(map[string]any)["profilePath"] = witnessPath
	result, err := BuildResult(input)
	if err != nil || result.ExitCode != 1 {
		t.Fatalf("expected a collected profile mismatch: exit=%d err=%v", result.ExitCode, err)
	}
	found := false
	for _, raw := range result.Manifest["files"].([]any) {
		file := raw.(map[string]any)
		if file["path"] != witnessPath {
			continue
		}
		found = true
		if file["source"] != "bootstrap_manifest" || file["contentKind"] != "json" {
			t.Fatal("profile mismatch changed the child materialization owner")
		}
		content := []byte(file["content"].(string))
		decoded, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := witnessplan.Build(decoded); err != nil {
			t.Fatalf("advertised witness-plan payload is not child-valid: %v", err)
		}
	}
	if !found {
		t.Fatal("witness materialization disappeared")
	}
}

func TestScaffoldRetainsChildFileRolesWithoutFilenameInference(t *testing.T) {
	for _, profile := range []string{cliexec.ProfilePath, cliexec.ProfileNPMOffline, cliexec.ProfilePythonModule} {
		t.Run(profile, func(t *testing.T) {
			python := ""
			if profile == cliexec.ProfilePythonModule {
				python = "/opt/python/bin/python"
			}
			renderer, err := cliexec.AdmitLauncherProfile(profile, python)
			if err != nil {
				t.Fatal(err)
			}
			input := validProjectStructureInput()
			input["bootstrap"].(map[string]any)["paths"].(map[string]any)["witnessPlanInputPath"] = "inputs/check.json"
			result, err := BuildResultWithRenderer(input, renderer)
			if err != nil || result.ExitCode != 0 {
				t.Fatalf("scaffold failed: exit=%d err=%v", result.ExitCode, err)
			}
			envelope, _, err := BuildEnvelopeFromResult(result)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, raw := range envelope["contextRefs"].([]any) {
				context := raw.(map[string]any)
				if context["ref"] == "inputs/check.json" {
					found = true
					if context["role"] != "command_registry" {
						t.Fatal("filename changed the child's semantic role")
					}
				}
			}
			if !found {
				t.Fatal("renamed witness context was not exercised")
			}
		})
	}
}

func TestScaffoldCommandRequiresItsExactMaterializationClass(t *testing.T) {
	for _, mismatch := range []string{"source", "contentKind", "materializationStatus"} {
		t.Run(mismatch, func(t *testing.T) {
			result, err := BuildResult(validProjectStructureInput())
			if err != nil || result.ExitCode != 0 {
				t.Fatal(err)
			}
			target := result.commands[0].inputRef
			for _, raw := range result.Manifest["files"].([]any) {
				file := raw.(map[string]any)
				if file["path"] == target {
					file[mismatch] = "unrelated_materialization"
				}
			}
			envelope, _, err := BuildEnvelopeFromResult(result)
			if err != nil {
				t.Fatal(err)
			}
			commands := envelope["commands"].([]any)
			if len(commands) != len(result.commands)-1 {
				t.Fatal("wrong materialization class did not remove exactly its command")
			}
			for _, raw := range commands {
				if raw.(map[string]any)["commandId"] == "proofkit.project-structure.command.001" {
					t.Fatal("path equality alone authorized a command")
				}
			}
		})
	}
}

func TestScaffoldRefusesCrossOwnerFileDirectoryConflicts(t *testing.T) {
	for _, rootKey := range []string{"repoProfileScaffoldInputPath", "bootstrapInputPath", "workflowInputPath"} {
		for _, rootIsParent := range []bool{false, true} {
			input := validProjectStructureInput()
			rootPath, childPath := "inputs/target/child.json", "inputs/target"
			if rootIsParent {
				rootPath, childPath = childPath, rootPath
			}
			input["paths"].(map[string]any)[rootKey] = rootPath
			input["bootstrap"].(map[string]any)["paths"].(map[string]any)["witnessPlanInputPath"] = childPath
			if _, err := BuildResult(input); err == nil {
				t.Fatalf("%s accepted a file/descendant conflict", rootKey)
			}
		}
	}
	input := validProjectStructureInput()
	input["paths"].(map[string]any)["bootstrapInputPath"] = "inputs/target"
	input["bootstrap"].(map[string]any)["paths"].(map[string]any)["witnessPlanInputPath"] = "inputs/target-sibling/child.json"
	if result, err := BuildResult(input); err != nil || result.ExitCode != 0 {
		t.Fatal("component-prefix sibling was incorrectly rejected")
	}
}
