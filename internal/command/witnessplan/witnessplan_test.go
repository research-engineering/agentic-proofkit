package witnessplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildAdmitsSafeCommandAndRejectsShellCommand(t *testing.T) {
	plan, err := Build(validWitnessPlanInput())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	commands := plan["commands"].([]any)
	groups := plan["parallelGroups"].([]any)
	if len(commands) != 1 || len(groups) != 1 {
		t.Fatalf("Build() plan=%#v, want one command in one group", plan)
	}

	input := validWitnessPlanInput()
	command := input["commands"].([]any)[0].(map[string]any)
	command["argv"] = []any{"sh", "-c", "go test ./..."}
	_, err = Build(input)
	if err == nil || !strings.Contains(err.Error(), "shell") {
		t.Fatalf("Build() accepted shell command: %v", err)
	}
}

func validWitnessPlanInput() map[string]any {
	return map[string]any{
		"vocabulary": map[string]any{
			"artifactKinds":                 []any{"report"},
			"credentialClasses":             []any{"github-token", "none"},
			"environmentClasses":            []any{"local-go"},
			"nonCacheableCredentialClasses": []any{"github-token"},
			"parallelGroups":                []any{"local"},
			"maxTimeoutMs":                  json.Number("10000"),
			"environmentClassPolicies": []any{
				map[string]any{
					"environmentClass":  "local-go",
					"networkPolicies":   []any{"none"},
					"credentialClasses": []any{"github-token", "none"},
					"cachePolicies":     []any{"disabled", "read-only"},
				},
			},
		},
		"commands": []any{
			map[string]any{
				"schemaVersion":   json.Number("1"),
				"id":              "proofkit.test-command",
				"cwd":             ".",
				"argv":            []any{"go", "test", "./..."},
				"timeoutMs":       json.Number("1000"),
				"networkPolicy":   "none",
				"credentialClass": "none",
				"cachePolicy":     "disabled",
				"parallelGroup":   "local",
				"environment": map[string]any{
					"inherit":   "none",
					"allowlist": []any{},
					"classes":   []any{"local-go"},
				},
				"expectedArtifacts": []any{
					map[string]any{"kind": "report", "path": "artifacts/proofkit/report.json", "required": true},
				},
				"exitCodePolicy": map[string]any{
					"kind":         "zero",
					"successCodes": []any{json.Number("0")},
				},
			},
		},
	}
}
