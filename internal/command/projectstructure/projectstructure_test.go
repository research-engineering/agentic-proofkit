package projectstructure

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildAdmitsProjectStructureScaffoldAndEmitsBoundedEnvelope(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.059212367917167148851747700357371540728657804008449562600146109586760618366690")
	result, err := BuildResult(validProjectStructureInput())
	if err != nil {
		t.Fatalf("BuildResult() error=%v", err)
	}
	if result.ExitCode != 0 || result.Record.State != "passed" {
		t.Fatalf("BuildResult() exit=%d state=%s ruleResults=%#v, want passed", result.ExitCode, result.Record.State, result.Record.RuleResults)
	}
	if len(anyArray(result.Manifest["sourceReports"])) != 3 {
		t.Fatalf("sourceReports=%#v, want 3 source report refs", result.Manifest["sourceReports"])
	}
	for _, raw := range anyArray(result.Manifest["nextCommands"]) {
		assertPackageExecutableCommand(t, raw.(string))
	}
	for _, raw := range anyArray(result.Manifest["sourceReports"]) {
		source := mapValue(raw)
		if source["stableHash"] == "" || source["state"] == "" {
			t.Fatalf("source report missing identity fields: %#v", source)
		}
	}

	envelope, exitCode, err := BuildEnvelope(validProjectStructureInput())
	if err != nil {
		t.Fatalf("BuildEnvelope() error=%v", err)
	}
	if exitCode != 0 {
		t.Fatalf("BuildEnvelope() exit=%d, want passed", exitCode)
	}
	bounds := mapValue(envelope["bounds"])
	if bounds["fanout"] != "bounded" {
		t.Fatalf("bounds=%#v, want bounded fanout", bounds)
	}
	if maxContextRefs, ok := bounds["maxContextRefs"].(int); !ok || maxContextRefs > envelopeContextLimit {
		t.Fatalf("bounds=%#v, want maxContextRefs <= %d", bounds, envelopeContextLimit)
	}
}

func TestBuildRejectsSecretLikeProjectStructureNonClaims(t *testing.T) {
	input := validProjectStructureInput()
	input["nonClaims"] = []any{"Authorization: Bearer abcdefghijklmnop"}

	_, err := BuildResult(input)
	if err == nil || !strings.Contains(err.Error(), "secret-like values") {
		t.Fatalf("BuildResult() error=%v, want secret-like rejection", err)
	}
}

func TestBuildRejectsProjectStructurePathDriftAndUnsafePaths(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.036326342746928185666570492555700463770379515182536792074657611113385319861032")
	cases := []struct {
		name      string
		mutate    func(map[string]any)
		wantError string
		wantFail  string
	}{
		{
			name: "binding path drift",
			mutate: func(input map[string]any) {
				input["repoProfileScaffold"].(map[string]any)["paths"].(map[string]any)["bindingPath"] = "proofkit/other-bindings.v1.json"
			},
			wantFail: "repo profile scaffold bindingPath must match bootstrap proofBindingPath",
		},
		{
			name: "unsafe bootstrap input path",
			mutate: func(input map[string]any) {
				input["paths"].(map[string]any)["bootstrapInputPath"] = "../proofkit/bootstrap.json"
			},
			wantError: "must not escape the repository root",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validProjectStructureInput()
			item.mutate(input)

			result, err := BuildResult(input)
			if item.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), item.wantError) {
					t.Fatalf("BuildResult() error=%v, want %q", err, item.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildResult() error=%v", err)
			}
			if result.ExitCode == 0 || result.Record.State != "failed" {
				t.Fatalf("BuildResult() exit=%d state=%s, want failed", result.ExitCode, result.Record.State)
			}
			if !projectStructureRuleMessageContains(result.Record.RuleResults, item.wantFail) {
				t.Fatalf("ruleResults=%#v, want %q", result.Record.RuleResults, item.wantFail)
			}
		})
	}
}

func validProjectStructureInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"scaffoldId":    "proofkit.test.project-structure",
		"nonClaims":     []any{"Project structure test input does not write files."},
		"paths": map[string]any{
			"bootstrapInputPath":           "proofkit/bootstrap.v1.json",
			"repoProfileScaffoldInputPath": "proofkit/repo-profile-scaffold.v1.json",
			"workflowInputPath":            "proofkit/adoption-workflow.v1.json",
		},
		"workflow": map[string]any{
			"nonClaims":  []any{"Project structure workflow test input does not execute commands."},
			"scenario":   "new_repository",
			"workflowId": "proofkit.test.workflow",
		},
		"repoProfileScaffold": validRepoProfileScaffoldInput(),
		"bootstrap":           validProjectBootstrapInput(),
	}
}

func validRepoProfileScaffoldInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"planId":        "proofkit.test.repo-profile-scaffold",
		"presetId":      "typescript_workspace",
		"repository": map[string]any{
			"name":             "consumer-repo",
			"primaryLanguages": []any{"go"},
			"profilePath":      "proofkit/repo-profile.v1.json",
			"rootPackageName":  "consumer-repo",
		},
		"paths": map[string]any{
			"bindingPath":           "proofkit/requirement-proof-bindings.v1.json",
			"generatedArtifacts":    []any{},
			"policyPath":            "proofkit/repo-profile.v1.json",
			"proofLikePaths":        []any{"docs/specs/review/requirements.v1.json"},
			"retiredProofLikePaths": []any{},
			"routerPath":            "AGENTS.md",
			"specGlobs":             []any{"docs/specs/**/*.json"},
		},
		"requirements": map[string]any{
			"idPattern": "REQ-CONSUMER-[0-9]+",
		},
		"environmentClasses": []any{"local-go"},
		"commandMatcherHints": []any{
			map[string]any{
				"allowedScripts":  []any{"check"},
				"credentialClass": "none",
				"id":              "consumer.check",
				"kind":            "bun_repo_script",
				"networkPolicy":   "none",
				"parallelGroup":   "local",
			},
		},
		"nonClaims": []any{"Repo profile scaffold test input does not prove repository facts."},
	}
}

func validProjectBootstrapInput() map[string]any {
	return map[string]any{
		"schemaVersion":     json.Number("1"),
		"bootstrapId":       "proofkit.test.bootstrap",
		"packageVersionRef": "agentic-proofkit@0.1.95",
		"repository": map[string]any{
			"customRuleBoundary": "profile_only",
			"primaryLanguages":   []any{"go"},
			"profilePath":        "proofkit/repo-profile.v1.json",
			"repositoryClass":    "go_cli",
			"repositoryId":       "proofkit.test.repo",
			"verifierCodeCopied": false,
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
		"module": map[string]any{
			"moduleId":       "proofkit.test.module",
			"requirementIds": []any{"REQ-CONSUMER-001"},
			"specPath":       "docs/specs/review/requirements.v1.json",
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
					"id":              "consumer.check",
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
		"proofBindingPath": "proofkit/requirement-proof-bindings.v1.json",
		"guidanceMode":     "observe",
		"checkedScope":     "none",
		"touchedRuleIds":   []any{},
		"commands":         []any{"agentic-proofkit gradual-adoption --input proofkit/profile.json"},
		"nonClaims":        []any{"Bootstrap test input does not prove rollout readiness."},
		"paths": map[string]any{
			"adoptionGuidancePath":       "proofkit/adoption-guidance.v1.json",
			"adoptionProfilePath":        "proofkit/adoption-profile.v1.json",
			"adoptionReportArtifactPath": "artifacts/proofkit/adoption.json",
			"guidanceReportArtifactPath": "artifacts/proofkit/guidance.json",
			"witnessPlanInputPath":       "proofkit/witness-plan.v1.json",
		},
		"ownerRoute": map[string]any{
			"evidencePaths":     []any{"artifacts/proofkit/adoption.json"},
			"primaryOwner":      "repo-maintainers",
			"proofBindingPaths": []any{"proofkit/requirement-proof-bindings.v1.json"},
			"specPaths":         []any{"docs/specs/review/requirements.v1.json"},
		},
	}
}

func projectStructureRuleMessageContains(results []report.RuleResult, needle string) bool {
	for _, raw := range results {
		if strings.Contains(raw.Message, needle) {
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
