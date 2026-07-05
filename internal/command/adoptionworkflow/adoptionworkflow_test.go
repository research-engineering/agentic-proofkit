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
	if result.Plan["planState"] != "ready_for_caller_review" || len(result.Plan["blockers"].([]any)) != 0 {
		t.Fatalf("plan state/blockers=%v/%#v, want ready without blockers", result.Plan["planState"], result.Plan["blockers"])
	}
	command := firstWorkflowCommand(t, result.Plan)
	argv := command["argv"].([]any)
	if strings.Join([]string{argv[0].(string), argv[1].(string), argv[2].(string)}, " ") != "agentic-proofkit release-authority --input" {
		t.Fatalf("argv prefix=%#v, want fixed proofkit command route", argv)
	}
	if got := argv[3].(string); got != "proofkit/release-authority.v1.json" {
		t.Fatalf("release authority input path=%q", got)
	}
	inputRefIDs := command["inputRefIds"].([]any)
	if len(inputRefIDs) != 1 || inputRefIDs[0] != "proofkit.release-authority" {
		t.Fatalf("inputRefIds=%#v, want release authority ref", inputRefIDs)
	}
	if command["owner"] != "consumer_repository" || !strings.Contains(command["nonClaim"].(string), "do not execute commands") {
		t.Fatalf("command route lost caller-owned non-claim boundary: %#v", command)
	}
	nonClaims := result.Plan["nonClaims"].([]any)
	if !anyStringContains(nonClaims, "Adoption workflow plans do not execute native witnesses or planned commands.") {
		t.Fatalf("workflow nonClaims missing execution boundary: %#v", nonClaims)
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

func anyStringContains(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
