package adoptionworkflow

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildRejectsUnknownInputRefField(t *testing.T) {
	input := validWorkflowInput()
	input["inputRefs"].([]any)[0].(map[string]any)["implicitCommand"] = true

	_, err := BuildResult(input)
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("BuildResult() error=%v, want unsupported field rejection", err)
	}
}

func TestBuildGeneratesBoundedCommandArgv(t *testing.T) {
	result, err := BuildResult(validWorkflowInput())
	if err != nil {
		t.Fatalf("BuildResult() error=%v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("BuildResult() exit=%d, want ready workflow", result.ExitCode)
	}
	command := firstWorkflowCommand(t, result.Plan)
	argv := command["argv"].([]any)
	if strings.Join([]string{argv[0].(string), argv[1].(string), argv[2].(string)}, " ") != "agentic-proofkit release-authority --input" {
		t.Fatalf("argv prefix=%#v, want fixed proofkit command route", argv)
	}
}

func TestBuildRoutesWitnessPlanRefToSchedulerPlanAdmission(t *testing.T) {
	input := validWorkflowInput()
	input["scenario"] = "new_repository"
	input["presetId"] = "python_service"
	input["inputRefs"] = []any{
		map[string]any{
			"inputKind": "gradual_adoption_bootstrap",
			"path":      "proofkit/bootstrap.json",
			"refId":     "proofkit.bootstrap",
		},
		map[string]any{
			"inputKind": "gradual_adoption_guidance",
			"path":      "proofkit/guidance.json",
			"refId":     "proofkit.guidance",
		},
		map[string]any{
			"inputKind": "repo_profile_scaffold",
			"path":      "proofkit/scaffold-profile-plan.json",
			"refId":     "proofkit.scaffold-profile",
		},
		map[string]any{
			"inputKind": "requirement_bindings",
			"path":      "proofkit/requirement-bindings.json",
			"refId":     "proofkit.requirement-bindings",
		},
		map[string]any{
			"inputKind": "witness_plan",
			"path":      "proofkit/witness-plan.json",
			"refId":     "proofkit.witness-plan",
		},
	}

	result, err := BuildResult(input)
	if err != nil {
		t.Fatalf("BuildResult() error=%v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("BuildResult() exit=%d, want ready workflow", result.ExitCode)
	}
	command := workflowCommand(t, result.Plan, "proofkit.adoption-workflow.command.witness-scheduler-plan")
	argv := command["argv"].([]any)
	if strings.Join([]string{argv[0].(string), argv[1].(string), argv[2].(string)}, " ") != "agentic-proofkit witness-scheduler-plan --input" {
		t.Fatalf("argv prefix=%#v, want witness-scheduler-plan route", argv)
	}
	if got := argv[3].(string); got != "proofkit/witness-plan.json" {
		t.Fatalf("witness scheduler input=%q, want proofkit/witness-plan.json", got)
	}
}

func validWorkflowInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"workflowId":    "proofkit.test.workflow",
		"scenario":      "release_channel",
		"presetId":      nil,
		"inputRefs": []any{
			map[string]any{
				"inputKind": "release_authority",
				"path":      "proofkit/release-authority.v1.json",
				"refId":     "proofkit.release-authority",
			},
			map[string]any{
				"inputKind": "registry_consumer",
				"path":      "proofkit/registry-consumer.v1.json",
				"refId":     "proofkit.registry-consumer",
			},
		},
		"nonClaims": []any{"Adoption workflow test input does not execute generated commands."},
	}
}

func firstWorkflowCommand(t *testing.T, plan map[string]any) map[string]any {
	t.Helper()
	return workflowCommand(t, plan, "proofkit.adoption-workflow.command.release-authority")
}

func workflowCommand(t *testing.T, plan map[string]any, commandID string) map[string]any {
	t.Helper()
	for _, rawPhase := range plan["phases"].([]any) {
		phase := rawPhase.(map[string]any)
		for _, rawCommand := range phase["commands"].([]any) {
			command := rawCommand.(map[string]any)
			if command["commandId"] == commandID {
				return command
			}
		}
	}
	t.Fatalf("%s command not found", commandID)
	return nil
}
