package repoprofileadmission

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildAdmitsValidRepoProfileAndRejectsRootPackageMismatch(t *testing.T) {
	record, exitCode, err := Build(validRepoProfileInput())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		encoded, _ := json.Marshal(record)
		t.Fatalf("Build() exit=%d record=%s, want passed", exitCode, string(encoded))
	}

	input := validRepoProfileInput()
	input["facts"].(map[string]any)["rootPackageName"] = "other-root"
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build() mismatch error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() accepted rootPackageName mismatch: exit=%d state=%s", exitCode, record.State)
	}
	assertRecordContains(t, record.JSONValue(), "rootPackageName must match")
}

func TestBuildRejectsUnknownRepoProfileAdmissionFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "top level",
			mutate: func(input map[string]any) {
				input["ambientPolicy"] = true
			},
		},
		{
			name: "facts",
			mutate: func(input map[string]any) {
				input["facts"].(map[string]any)["ambientPolicy"] = true
			},
		},
		{
			name: "policy",
			mutate: func(input map[string]any) {
				input["policy"].(map[string]any)["ambientPolicy"] = true
			},
		},
		{
			name: "environment policy",
			mutate: func(input map[string]any) {
				policy := input["policy"].(map[string]any)
				policy["environmentPolicy"].(map[string]any)["ambientPolicy"] = true
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validRepoProfileInput()
			item.mutate(input)
			record, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() unexpected error = %v", err)
			}
			if exitCode == 0 || record.State != "failed" {
				t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
			}
			if !strings.Contains(record.RuleResults[0].Message, "unsupported field") {
				t.Fatalf("failure message=%q, want unsupported field", record.RuleResults[0].Message)
			}
		})
	}
}

func TestBuildRejectsSchemeAndDriveLikeRepoProfilePaths(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "tracked file scheme",
			mutate: func(input map[string]any) {
				input["facts"].(map[string]any)["trackedFiles"] = []any{"file:docs/INDEX.md"}
			},
		},
		{
			name: "tracked file drive",
			mutate: func(input map[string]any) {
				input["facts"].(map[string]any)["trackedFiles"] = []any{"C:/outside/INDEX.md"}
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validRepoProfileInput()
			item.mutate(input)
			record, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() unexpected error = %v", err)
			}
			if exitCode == 0 || record.State != "failed" {
				t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
			}
			if !strings.Contains(record.RuleResults[0].Message, "repository-relative POSIX path") {
				t.Fatalf("failure message=%q, want path rejection", record.RuleResults[0].Message)
			}
		})
	}
}

func TestBuildRejectsShellControlCommandEnvironmentPair(t *testing.T) {
	input := validRepoProfileInput()
	input["facts"].(map[string]any)["commandEnvironmentPairs"] = []any{
		map[string]any{"command": "go test ./... && curl example.test", "environmentClasses": []any{"local-go"}},
	}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	if !strings.Contains(record.RuleResults[0].Message, "display-only command text") {
		t.Fatalf("failure message=%q, want display-only command rejection", record.RuleResults[0].Message)
	}
}

func assertRecordContains(t *testing.T, value any, want string) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	if !strings.Contains(string(encoded), want) {
		t.Fatalf("record missing %q: %s", want, string(encoded))
	}
}

func validRepoProfileInput() map[string]any {
	return map[string]any{
		"profile": map[string]any{
			"schema": "proofkit.repo-profile.v1",
			"repository": map[string]any{
				"name":             "example",
				"primaryLanguages": []any{"go"},
				"rootPackageName":  "example-root",
			},
			"documents": map[string]any{
				"policyPath":         "docs/docs-policy.yaml",
				"routerPath":         "docs/INDEX.md",
				"generatedArtifacts": []any{},
			},
			"requirements": map[string]any{
				"idPattern": "REQ-[A-Z0-9-]+",
				"specGlobs": []any{"docs/specs/example/requirements.v1.json"},
			},
			"proofs": map[string]any{
				"bindingPath":           "docs/contracts/bindings.json",
				"environmentClasses":    []any{"local-go"},
				"proofLikePaths":        []any{"docs/contracts/*.json"},
				"retiredProofLikePaths": []any{},
			},
			"commandMatchers": []any{
				map[string]any{
					"allowedArgv":     []any{"go", "test", "./..."},
					"credentialClass": "none",
					"id":              "proofkit.test.go",
					"kind":            "exact_argv",
					"networkPolicy":   "none",
					"parallelGroup":   "local",
				},
			},
			"nonClaims": []any{"Repo profile test input does not read repository state."},
		},
		"facts": map[string]any{
			"commandEnvironmentPairs": []any{
				map[string]any{"command": "go test ./...", "environmentClasses": []any{"local-go"}},
			},
			"docsPolicyGeneratedArtifacts": []any{},
			"packageScripts":               []any{},
			"rootPackageName":              "example-root",
			"rootScripts":                  []any{},
			"trackedFiles": []any{
				"docs/INDEX.md",
				"docs/contracts/bindings.json",
				"docs/docs-policy.yaml",
				"docs/specs/example/requirements.v1.json",
			},
		},
		"policy": map[string]any{
			"environmentPolicy": map[string]any{
				"liveGithubRequiredClasses":  []any{},
				"localSecretRequiredClasses": []any{},
			},
			"packageNamePattern": nil,
		},
	}
}
