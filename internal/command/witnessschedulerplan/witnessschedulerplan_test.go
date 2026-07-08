package witnessschedulerplan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildRejectsNetworkMetadataContradictions(t *testing.T) {
	input := validSchedulerPlanInput()
	schedulerPolicy(input)["sideEffectClass"] = "network"

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("build scheduler plan: %v", err)
	}
	if exitCode != 1 || record.State != "failed" || !recordContains(record.Diagnostics, "non-networked command") {
		t.Fatalf("expected non-networked side-effect failure, exitCode=%d record=%#v", exitCode, record)
	}
}

func TestBuildRejectsUnsafeParallelWriteCollision(t *testing.T) {
	input := validSchedulerPlanInput()
	command(input)["id"] = "proofkit.left"
	schedulerPolicy(input)["commandId"] = "proofkit.left"
	rightCommand := cloneMap(command(input))
	rightCommand["id"] = "proofkit.right"
	rightPolicy := cloneMap(schedulerPolicy(input))
	rightPolicy["commandId"] = "proofkit.right"
	input["commands"] = append(input["commands"].([]any), rightCommand)
	input["policies"] = append(input["policies"].([]any), rightPolicy)

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("build scheduler plan: %v", err)
	}
	if exitCode != 1 || record.State != "failed" || !recordContains(record.Diagnostics, "write/write resource collision") {
		t.Fatalf("expected write/write collision, exitCode=%d record=%#v", exitCode, record)
	}
}

func TestBuildRejectsDestructiveAutomaticRetry(t *testing.T) {
	input := validSchedulerPlanInput()
	item := schedulerPolicy(input)
	item["sideEffectClass"] = "destructive"
	item["exclusiveLocks"] = []any{"lock.proofkit.test"}
	item["retryPolicy"] = map[string]any{"kind": "bounded", "maxAttempts": json.Number("2")}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("build scheduler plan: %v", err)
	}
	if exitCode != 1 || record.State != "failed" || !recordContains(record.Diagnostics, "must not retry automatically") {
		t.Fatalf("expected destructive retry failure, exitCode=%d record=%#v", exitCode, record)
	}
}

func TestBuildRejectsSecretLikeReportVisibleText(t *testing.T) {
	secret := "Authorization: Bearer abcdefghijklmnop"
	input := validSchedulerPlanInput()
	input["nonClaims"] = []any{secret}

	_, _, err := Build(input)
	if err == nil {
		t.Fatal("Build() accepted secret-shaped nonClaim")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked secret-shaped caller text: %v", err)
	}
	if !strings.Contains(err.Error(), "secret-like values") {
		t.Fatalf("error=%v, want secret-like rejection", err)
	}
}

func TestEvaluateProjectsAdmittedCommandLinkageFacts(t *testing.T) {
	projection, record, exitCode, err := Evaluate(validSchedulerPlanInput())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Evaluate() exit=%d state=%s, want passed", exitCode, record.State)
	}
	if projection.SchedulerPlanID != "proofkit.test.scheduler" {
		t.Fatalf("SchedulerPlanID=%q, want proofkit.test.scheduler", projection.SchedulerPlanID)
	}
	if len(projection.Commands) != 1 {
		t.Fatalf("Commands=%#v, want one command projection", projection.Commands)
	}
	command := projection.Commands[0]
	if command.ID != "proofkit.test-command" || len(command.EnvironmentClasses) != 1 || command.EnvironmentClasses[0] != "local-go" {
		t.Fatalf("Command projection=%#v, want admitted id and environment class", command)
	}
}

func validSchedulerPlanInput() map[string]any {
	return map[string]any{
		"schemaVersion":   json.Number("1"),
		"schedulerPlanId": "proofkit.test.scheduler",
		"nonClaims":       []any{"Synthetic scheduler input does not execute commands."},
		"vocabulary": map[string]any{
			"artifactKinds":                 []any{"report"},
			"credentialClasses":             []any{"none"},
			"environmentClasses":            []any{"local-go"},
			"environmentClassPolicies":      []any{map[string]any{"environmentClass": "local-go", "networkPolicies": []any{"none"}, "credentialClasses": []any{"none"}, "cachePolicies": []any{"disabled"}}},
			"parallelGroups":                []any{"local"},
			"nonCacheableCredentialClasses": []any{},
			"maxTimeoutMs":                  json.Number("10000"),
		},
		"commands": []any{
			map[string]any{
				"schemaVersion":   json.Number("1"),
				"id":              "proofkit.test-command",
				"cwd":             ".",
				"argv":            []any{"go", "test", "./..."},
				"environment":     map[string]any{"inherit": "none", "allowlist": []any{}, "classes": []any{"local-go"}},
				"timeoutMs":       json.Number("1000"),
				"networkPolicy":   "none",
				"credentialClass": "none",
				"cachePolicy":     "disabled",
				"expectedArtifacts": []any{
					map[string]any{"kind": "report", "path": "artifacts/proofkit/report.json", "required": true},
				},
				"parallelGroup":  "local",
				"exitCodePolicy": map[string]any{"kind": "zero", "successCodes": []any{json.Number("0")}},
			},
		},
		"policies": []any{
			map[string]any{
				"commandId":           "proofkit.test-command",
				"inputSelectors":      []any{"cmd"},
				"outputSelectors":     []any{"artifacts/proofkit/report.json"},
				"resourceReads":       []any{"resource.proofkit.source"},
				"resourceWrites":      []any{"resource.proofkit.local-artifacts"},
				"exclusiveLocks":      []any{},
				"sideEffectClass":     "local_write",
				"deterministicOutput": true,
				"cacheAdmissionRefs":  []any{},
				"retryPolicy":         map[string]any{"kind": "none", "maxAttempts": json.Number("1")},
				"cancellationPolicy":  map[string]any{"kind": "cooperative", "graceMs": json.Number("5000")},
				"timeoutPolicy":       map[string]any{"kind": "bounded", "timeoutMs": json.Number("1000")},
				"nonClaims":           []any{"Synthetic scheduler policy does not prove command success."},
			},
		},
	}
}

func command(input map[string]any) map[string]any {
	return input["commands"].([]any)[0].(map[string]any)
}

func schedulerPolicy(input map[string]any) map[string]any {
	return input["policies"].([]any)[0].(map[string]any)
}

func cloneMap(input map[string]any) map[string]any {
	encoded, err := json.Marshal(input)
	if err != nil {
		panic(err)
	}
	var output map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&output); err != nil {
		panic(err)
	}
	return output
}

func recordContains(diagnostics any, needle string) bool {
	return strings.Contains(strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(toJSON(diagnostics), "\\n", " "), "\\t", " ")), needle)
}

func toJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}
