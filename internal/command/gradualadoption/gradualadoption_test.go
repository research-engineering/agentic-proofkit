package gradualadoption

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestBuildRejectsUnknownGradualAdoptionFields(t *testing.T) {
	input := validAdoptionInput()
	input["ambientAuthority"] = true

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("Build() error=%v, want unsupported field rejection", err)
	}
}

func TestBuildReportsUnknownNestedGradualAdoptionFields(t *testing.T) {
	input := validAdoptionInput()
	input["repository"].(map[string]any)["ambientAuthority"] = true

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error=%v", err)
	}
	if exitCode == 0 || record["state"] != "failed" {
		t.Fatalf("Build() exit=%d state=%v, want failed", exitCode, record["state"])
	}
	if !ruleMessageContains(record["ruleResults"], "unsupported field") {
		t.Fatalf("ruleResults=%#v, want unsupported field failure", record["ruleResults"])
	}
}

func TestBuildRejectsRollbackShellControlCommand(t *testing.T) {
	input := validAdoptionInput()
	input["rollback"].(map[string]any)["disableCommand"] = "remove proofkit report && curl example.test"

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error=%v", err)
	}
	if exitCode == 0 || record["state"] != "failed" {
		t.Fatalf("Build() exit=%d state=%v, want failed", exitCode, record["state"])
	}
	if !ruleMessageContains(record["ruleResults"], "display-only command text") {
		t.Fatalf("ruleResults=%#v, want display-only command failure", record["ruleResults"])
	}
}

func TestBootstrapRejectsShellControlGuidanceCommand(t *testing.T) {
	_, err := displayCommandsFromStrings([]string{"agentic-proofkit gradual-adoption && curl example.test"}, "bootstrap commands")
	if err == nil || !strings.Contains(err.Error(), "display-only command text") {
		t.Fatalf("displayCommandsFromStrings() error=%v, want display-only command rejection", err)
	}
}

func TestBootstrapPreservesCallerDisplayCommandInGuidancePayload(t *testing.T) {
	result, err := BuildBootstrapResult(validBootstrapInput())
	if err != nil {
		t.Fatalf("BuildBootstrapResult() error=%v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("BuildBootstrapResult() exit=%d report=%#v, want passed", result.ExitCode, result.Record.JSONValue())
	}
	guidance := result.Payloads["adoptionGuidance"].(map[string]any)
	agentGuidance := guidance["agentGuidance"].(map[string]any)
	commands := anyStrings(agentGuidance["commands"])
	if !containsString(commands, "go test ./internal/command/gradualadoption") {
		t.Fatalf("caller-provided bootstrap command was not preserved: %#v", commands)
	}
	if !containsString(commands, "agentic-proofkit gradual-adoption --input proofkit/profile.json") {
		t.Fatalf("generated bootstrap command missing: %#v", commands)
	}
	if !containsString(commands, "agentic-proofkit witness-scheduler-plan --input proofkit/witness-plan.json") {
		t.Fatalf("generated witness scheduler command missing: %#v", commands)
	}
	if containsString(commands, "agentic-proofkit witness-plan --input proofkit/witness-plan.json") {
		t.Fatalf("generated bootstrap command uses catalog command for scheduler-plan fixture: %#v", commands)
	}
	for _, command := range result.NextCommands {
		assertPackageExecutableCommand(t, command)
	}
}

func TestBootstrapRejectsUnknownRootAndNestedFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "root", mutate: func(input map[string]any) { input["ambientAuthority"] = true }},
		{name: "paths", mutate: func(input map[string]any) { input["paths"].(map[string]any)["ambientAuthority"] = true }},
		{name: "module", mutate: func(input map[string]any) { input["module"].(map[string]any)["ambientAuthority"] = true }},
		{name: "owner route", mutate: func(input map[string]any) { input["ownerRoute"].(map[string]any)["ambientAuthority"] = true }},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validBootstrapInput()
			item.mutate(input)
			record, exitCode, err := BuildBootstrap(input)
			if err != nil {
				if !strings.Contains(err.Error(), "unsupported field") {
					t.Fatalf("BuildBootstrap() error=%v, want unsupported field", err)
				}
				return
			}
			if exitCode == 0 || !ruleMessageContains(reportRuleResults(record), "unsupported field") {
				t.Fatalf("BuildBootstrap() exit=%d record=%#v, want unsupported field failure", exitCode, record)
			}
		})
	}
}

func TestGuidanceRejectsUnknownRootAndNestedFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "root", mutate: func(input map[string]any) { input["ambientAuthority"] = true }},
		{name: "scope evidence", mutate: func(input map[string]any) { input["scopeEvidence"].(map[string]any)["ambientAuthority"] = true }},
		{name: "owner route", mutate: func(input map[string]any) { input["ownerRoute"].(map[string]any)["ambientAuthority"] = true }},
		{name: "agent guidance", mutate: func(input map[string]any) { input["agentGuidance"].(map[string]any)["ambientAuthority"] = true }},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validGuidanceInput()
			item.mutate(input)
			result, exitCode, err := BuildGuidance(input, GuidanceOptions{})
			if err != nil {
				if !strings.Contains(err.Error(), "unsupported field") {
					t.Fatalf("BuildGuidance() error=%v, want unsupported field", err)
				}
				return
			}
			if exitCode == 0 || !ruleMessageContains(result["ruleResults"], "unsupported field") {
				t.Fatalf("BuildGuidance() exit=%d result=%#v, want unsupported field failure", exitCode, result)
			}
		})
	}
}

func validAdoptionInput() map[string]any {
	return map[string]any{
		"schemaVersion":     json.Number("1"),
		"adoptionId":        "proofkit.test.adoption",
		"adoptionMode":      "non_blocking",
		"packageVersionRef": "agentic-proofkit@0.1.95",
		"rolloutClaim":      false,
		"nonClaims":         []any{"Gradual adoption test input does not prove rollout readiness."},
		"repository": map[string]any{
			"customRuleBoundary": "profile_only",
			"primaryLanguages":   []any{"go"},
			"profilePath":        "proofkit/profile.json",
			"repositoryClass":    "go_cli",
			"repositoryId":       "proofkit.test.repo",
			"verifierCodeCopied": false,
		},
		"module": map[string]any{
			"moduleId":       "proofkit.test.module",
			"requirementIds": []any{"REQ-PROOFKIT-TEST-001"},
			"specPath":       "docs/specs/test/requirements.v1.json",
		},
		"proofBinding": map[string]any{
			"bindingFormat":     "requirement_to_witness",
			"bindingPath":       "proofkit/proof-bindings.json",
			"requirementIds":    []any{"REQ-PROOFKIT-TEST-001"},
			"witnessCommandIds": []any{"proofkit.test.command"},
		},
		"nativeWitnesses": map[string]any{
			"vocabulary": map[string]any{
				"artifactKinds":      []any{"json"},
				"credentialClasses":  []any{"none"},
				"environmentClasses": []any{"local-go"},
				"environmentClassPolicies": []any{
					map[string]any{
						"cachePolicies":     []any{"read-only"},
						"credentialClasses": []any{"none"},
						"environmentClass":  "local-go",
						"networkPolicies":   []any{"none"},
					},
				},
				"parallelGroups": []any{"local-go"},
			},
			"commands": []any{
				map[string]any{
					"schemaVersion":   json.Number("1"),
					"id":              "proofkit.test.command",
					"argv":            []any{"go", "test", "./..."},
					"cachePolicy":     "read-only",
					"credentialClass": "none",
					"cwd":             ".",
					"environment": map[string]any{
						"allowlist": []any{},
						"classes":   []any{"local-go"},
						"inherit":   "none",
					},
					"exitCodePolicy": map[string]any{
						"kind":         "zero",
						"successCodes": []any{json.Number("0")},
					},
					"expectedArtifacts": []any{},
					"networkPolicy":     "none",
					"parallelGroup":     "local-go",
					"timeoutMs":         json.Number("60000"),
				},
			},
		},
		"agentReport": map[string]any{
			"artifactPath":   "artifacts/proofkit/gradual-adoption.json",
			"outputMode":     "non_blocking",
			"reportKind":     "proofkit.gradual-adoption",
			"routeQuestions": []any{"what changed", "what proves it", "who owns it"},
			"schemaId":       "proofkit.gradual-adoption-profile.v1",
		},
		"budget": map[string]any{
			"copiedVerifierFileCount": json.Number("0"),
			"customRuleCount":         json.Number("0"),
			"maxAddedSeconds":         json.Number("10"),
			"maxCustomRuleCount":      json.Number("0"),
			"maxProfileLines":         json.Number("80"),
			"maxSetupMinutes":         json.Number("20"),
			"profileLines":            json.Number("42"),
		},
		"rollback": map[string]any{
			"disableCommand": "remove proofkit gradual-adoption report from non-blocking CI",
			"owner":          "repo-maintainers",
			"versionPin":     "agentic-proofkit@0.1.94",
		},
	}
}

func validBootstrapInput() map[string]any {
	adoption := validAdoptionInput()
	return map[string]any{
		"schemaVersion":     json.Number("1"),
		"bootstrapId":       "proofkit.test.bootstrap",
		"packageVersionRef": adoption["packageVersionRef"],
		"repository":        adoption["repository"],
		"budget":            adoption["budget"],
		"rollback":          adoption["rollback"],
		"module":            adoption["module"],
		"nativeWitnesses":   adoption["nativeWitnesses"],
		"proofBindingPath":  "proofkit/proof-bindings.json",
		"guidanceMode":      "observe",
		"checkedScope":      "none",
		"touchedRuleIds":    []any{},
		"commands":          []any{"go test ./internal/command/gradualadoption"},
		"nonClaims":         []any{"Bootstrap test input does not prove rollout readiness."},
		"paths": map[string]any{
			"adoptionGuidancePath":       "proofkit/guidance.json",
			"adoptionProfilePath":        "proofkit/profile.json",
			"adoptionReportArtifactPath": "artifacts/proofkit/adoption.json",
			"guidanceReportArtifactPath": "artifacts/proofkit/guidance.json",
			"witnessPlanInputPath":       "proofkit/witness-plan.json",
		},
		"ownerRoute": map[string]any{
			"evidencePaths":     []any{"artifacts/proofkit/adoption.json"},
			"primaryOwner":      "repo-maintainers",
			"proofBindingPaths": []any{"proofkit/proof-bindings.json"},
			"specPaths":         []any{"docs/specs/test/requirements.v1.json"},
		},
	}
}

func validGuidanceInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"guidanceId":    "proofkit.test.guidance",
		"guidanceMode":  "observe",
		"sourceReport": map[string]any{
			"reportId":      "proofkit.test.source",
			"reportKind":    "proofkit.test.source",
			"schemaVersion": json.Number("1"),
			"state":         "passed",
			"ruleResults":   []any{},
		},
		"scopeEvidence": map[string]any{
			"basis":          "caller_provided_touched_rule_ids",
			"checkedScope":   "none",
			"touchedRuleIds": []any{},
		},
		"ownerRoute": map[string]any{
			"evidencePaths":     []any{"artifacts/proofkit/source.json"},
			"primaryOwner":      "repo-maintainers",
			"proofBindingPaths": []any{"proofkit/proof-bindings.json"},
			"specPaths":         []any{"docs/specs/test/requirements.v1.json"},
		},
		"agentGuidance": map[string]any{
			"artifactPath":                     "artifacts/proofkit/guidance.json",
			"blockedPreconditions":             []any{},
			"callerSuggestedAutofixCandidates": []any{},
			"commands":                         []any{},
			"minimalAdoptionPath":              []any{"Keep proofkit adoption non-blocking until owner review."},
			"proofBindingsMissing":             []any{},
			"reportKind":                       "proofkit.gradual-adoption-guidance",
			"requiredNextActions":              []any{},
			"routeQuestions":                   []any{"what changed", "what proves it", "who owns it"},
			"schemaId":                         "proofkit.gradual-adoption-guidance.v1",
		},
		"modernization": map[string]any{
			"candidateBoundaries":         []any{},
			"promoteOnlyAfterOwnerReview": true,
		},
		"nonClaims": []any{"Guidance test input does not prove rollout readiness."},
	}
}

func ruleMessageContains(raw any, needle string) bool {
	values, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, value := range values {
		record := value.(map[string]any)
		if strings.Contains(record["message"].(string), needle) {
			return true
		}
	}
	return false
}

func reportRuleResults(record map[string]any) any {
	if rawReport, ok := record["report"].(map[string]any); ok {
		return rawReport["ruleResults"]
	}
	return record["ruleResults"]
}

func anyStrings(raw any) []string {
	values := raw.([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.(string))
	}
	return result
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func assertPackageExecutableCommand(t *testing.T, command string) {
	t.Helper()
	fields := strings.Fields(command)
	if len(fields) < 2 {
		t.Fatalf("generated command %q has no command name", command)
	}
	if fields[0] != cliexec.BinaryName {
		t.Fatalf("generated command %q uses binary %q, want %q", command, fields[0], cliexec.BinaryName)
	}
}
