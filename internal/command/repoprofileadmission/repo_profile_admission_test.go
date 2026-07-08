package repoprofileadmission

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestBuildAdmitsValidRepoProfileAndRejectsRootPackageMismatch(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.043504337756050392884249498699771665633165590624042065689844493508169838701202")
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

func TestBuildAdmitsOptionalInputSchemaVersionOne(t *testing.T) {
	input := validRepoProfileInput()
	input["schemaVersion"] = json.Number("1")
	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		encoded, _ := json.Marshal(record)
		t.Fatalf("Build() exit=%d record=%s, want passed", exitCode, string(encoded))
	}

	input = validRepoProfileInput()
	input["schemaVersion"] = json.Number("2")
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() admitted invalid schemaVersion: exit=%d state=%s", exitCode, record.State)
	}
	assertRecordContains(t, record.JSONValue(), "schemaVersion must be 1")
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
			encoded, _ := json.Marshal(record.JSONValue())
			if strings.Contains(string(encoded), "file:docs/INDEX.md") || strings.Contains(string(encoded), "C:/outside/INDEX.md") {
				t.Fatalf("Build() leaked rejected caller path: %s", encoded)
			}
		})
	}
}

func TestBuildRedactsCallerPathDiagnostics(t *testing.T) {
	input := validRepoProfileInput()
	profile := input["profile"].(map[string]any)
	documents := profile["documents"].(map[string]any)
	documents["policyPath"] = "docs/sk-proj-abcdefghijklmnop.md"

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	encoded, _ := json.Marshal(record.JSONValue())
	if strings.Contains(string(encoded), "abcdefghijklmnop") {
		t.Fatalf("Build() leaked caller path diagnostic: %s", encoded)
	}
}

func TestBuildRedactsGeneratedArtifactDiagnostics(t *testing.T) {
	input := validRepoProfileInput()
	profile := input["profile"].(map[string]any)
	documents := profile["documents"].(map[string]any)
	documents["generatedArtifacts"] = []any{
		map[string]any{
			"generator":     "scripts/generate-docs",
			"path":          "docs/ordinary-caller-path",
			"sourceOfTruth": []any{"docs/specs/example/requirements.v1.json"},
		},
	}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	encoded, _ := json.Marshal(record.JSONValue())
	if strings.Contains(string(encoded), "ordinary-caller-path") {
		t.Fatalf("Build() leaked generated artifact path diagnostic: %s", encoded)
	}
	if !strings.Contains(string(encoded), "must be mirrored in docs policy") {
		t.Fatalf("Build() lost generated artifact diagnostic class: %s", encoded)
	}
}

func TestBuildMinimizesRejectedCallerPathDiagnostics(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "profile path escape",
			mutate: func(input map[string]any) {
				input["profile"].(map[string]any)["documents"].(map[string]any)["policyPath"] = "../ordinary-caller-path"
			},
		},
		{
			name: "profile glob escape",
			mutate: func(input map[string]any) {
				input["profile"].(map[string]any)["requirements"].(map[string]any)["specGlobs"] = []any{"../ordinary-caller-path"}
			},
		},
		{
			name: "command matcher allowed test glob escape",
			mutate: func(input map[string]any) {
				matcher := input["profile"].(map[string]any)["commandMatchers"].([]any)[0].(map[string]any)
				matcher["allowedTestPathGlobs"] = []any{"../ordinary-caller-path"}
			},
		},
		{
			name: "unmatched valid spec glob",
			mutate: func(input map[string]any) {
				input["profile"].(map[string]any)["requirements"].(map[string]any)["specGlobs"] = []any{"docs/ordinary-caller-path/**/*.json"}
			},
			want: "matches no tracked files",
		},
		{
			name: "retired proof-like path still tracked",
			mutate: func(input map[string]any) {
				profile := input["profile"].(map[string]any)
				proofs := profile["proofs"].(map[string]any)
				proofs["retiredProofLikePaths"] = []any{"docs/ordinary-caller-path.md"}
				facts := input["facts"].(map[string]any)
				facts["trackedFiles"] = append(facts["trackedFiles"].([]any), "docs/ordinary-caller-path.md")
			},
			want: "retired proof-like path must not exist",
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
			encoded, _ := json.Marshal(record.JSONValue())
			if strings.Contains(string(encoded), "../ordinary-caller-path") || strings.Contains(string(encoded), "ordinary-caller-path") {
				t.Fatalf("Build() echoed rejected caller path: %s", encoded)
			}
			want := item.want
			if want == "" {
				want = "must not escape the repository root"
			}
			if !strings.Contains(string(encoded), want) {
				t.Fatalf("Build() lost stable diagnostic %q: %s", want, encoded)
			}
		})
	}
}

func TestBuildAdmitsExternalNetworkWithoutCredentialsThroughEnvironmentClassPolicy(t *testing.T) {
	input := validRepoProfileInput()
	profile := input["profile"].(map[string]any)
	proofs := profile["proofs"].(map[string]any)
	proofs["environmentClasses"] = []any{"external-public"}
	profile["commandMatchers"] = []any{
		map[string]any{
			"allowedArgv":     []any{"npm", "ci", "--dry-run"},
			"credentialClass": "none",
			"id":              "proofkit.test.npm-dry-run",
			"kind":            "exact_argv",
			"networkPolicy":   "external",
			"parallelGroup":   "network",
		},
	}
	input["facts"].(map[string]any)["commandEnvironmentPairs"] = []any{
		map[string]any{"command": "npm ci --dry-run", "environmentClasses": []any{"external-public"}},
	}
	input["policy"].(map[string]any)["environmentPolicy"] = map[string]any{
		"environmentClassPolicies": []any{
			map[string]any{
				"credentialClass":  "none",
				"environmentClass": "external-public",
				"networkPolicy":    "external",
			},
		},
		"liveGithubRequiredClasses":  []any{},
		"localSecretRequiredClasses": []any{},
	}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		encoded, _ := json.Marshal(record)
		t.Fatalf("Build() exit=%d record=%s, want passed", exitCode, string(encoded))
	}
}

func TestBuildRejectsExternalNetworkWithoutEnvironmentClassPolicy(t *testing.T) {
	input := validRepoProfileInput()
	profile := input["profile"].(map[string]any)
	proofs := profile["proofs"].(map[string]any)
	proofs["environmentClasses"] = []any{"external-public"}
	profile["commandMatchers"] = []any{
		map[string]any{
			"allowedArgv":     []any{"npm", "ci", "--dry-run"},
			"credentialClass": "none",
			"id":              "proofkit.test.npm-dry-run",
			"kind":            "exact_argv",
			"networkPolicy":   "external",
			"parallelGroup":   "network",
		},
	}
	input["facts"].(map[string]any)["commandEnvironmentPairs"] = []any{
		map[string]any{"command": "npm ci --dry-run", "environmentClasses": []any{"external-public"}},
	}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() admitted external network without tuple policy: exit=%d state=%s", exitCode, record.State)
	}
	assertRecordContains(t, record.JSONValue(), "command matchers admit no witness command/environment pair")
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
