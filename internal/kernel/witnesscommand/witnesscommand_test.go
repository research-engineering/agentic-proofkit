package witnesscommand

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAdmitWithVocabularyAcceptsExplicitCommandContract(t *testing.T) {
	command, err := AdmitWithVocabulary(validCommand(), validVocabulary())
	if err != nil {
		t.Fatalf("admit command: %v", err)
	}
	if command.ID != "proofkit.test-command" || command.Argv[0] != "go" {
		t.Fatalf("unexpected command: %#v", command)
	}
}

func TestAdmitWithVocabularyRejectsRiskCorpus(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "shell executable",
			mutate: func(command map[string]any) {
				command["argv"] = []any{"sh", "-c", "go test ./..."}
			},
			want: "shell",
		},
		{
			name: "windows shell executable",
			mutate: func(command map[string]any) {
				command["argv"] = []any{`C:\Windows\System32\cmd.exe`, "/c", "go test ./..."}
			},
			want: "shell",
		},
		{
			name: "alternative posix shell executable",
			mutate: func(command map[string]any) {
				command["argv"] = []any{"/bin/dash", "-c", "go test ./..."}
			},
			want: "shell",
		},
		{
			name: "alternative windows shell executable",
			mutate: func(command map[string]any) {
				command["argv"] = []any{`C:\Windows\System32\tcsh.exe`, "-c", "go test ./..."}
			},
			want: "shell",
		},
		{
			name: "busybox shell dispatcher",
			mutate: func(command map[string]any) {
				command["argv"] = []any{"busybox", "sh", "-c", "go test ./..."}
			},
			want: "shell",
		},
		{
			name: "env shell dispatcher",
			mutate: func(command map[string]any) {
				command["argv"] = []any{"/usr/bin/env", "bash", "-c", "go test ./..."}
			},
			want: "command dispatch",
		},
		{
			name: "secret shaped argv",
			mutate: func(command map[string]any) {
				command["argv"] = []any{"go", "test", "ghp_FAKEFAKE123456"}
			},
			want: "string array",
		},
		{
			name: "secret shaped id",
			mutate: func(command map[string]any) {
				command["id"] = "ghp_FAKEFAKE123456"
			},
			want: "secret-like values",
		},
		{
			name: "unsafe cwd",
			mutate: func(command map[string]any) {
				command["cwd"] = "../repo"
			},
			want: "escape the repository",
		},
		{
			name: "missing timeout",
			mutate: func(command map[string]any) {
				delete(command, "timeoutMs")
			},
			want: "timeoutMs",
		},
		{
			name: "float timeout",
			mutate: func(command map[string]any) {
				command["timeoutMs"] = float64(1000)
			},
			want: "timeoutMs",
		},
		{
			name: "fractional timeout",
			mutate: func(command map[string]any) {
				command["timeoutMs"] = json.Number("1000.5")
			},
			want: "timeoutMs",
		},
		{
			name: "unknown environment class",
			mutate: func(command map[string]any) {
				command["environment"].(map[string]any)["classes"] = []any{"local-python"}
			},
			want: "unsupported value",
		},
		{
			name: "cacheable credentialed command",
			mutate: func(command map[string]any) {
				command["credentialClass"] = "github-token"
				command["cachePolicy"] = "read-only"
			},
			want: "non-cacheable credentials",
		},
		{
			name: "environment policy denies network",
			mutate: func(command map[string]any) {
				command["networkPolicy"] = "external"
			},
			want: "does not admit networkPolicy",
		},
		{
			name: "duplicate artifact",
			mutate: func(command map[string]any) {
				artifact := command["expectedArtifacts"].([]any)[0]
				command["expectedArtifacts"] = []any{artifact, artifact}
			},
			want: "sorted and unique",
		},
		{
			name: "unsafe expected artifact path",
			mutate: func(command map[string]any) {
				artifact := command["expectedArtifacts"].([]any)[0].(map[string]any)
				artifact["path"] = "../artifacts/report.json"
			},
			want: "escape the repository",
		},
		{
			name: "float success code",
			mutate: func(command map[string]any) {
				command["exitCodePolicy"].(map[string]any)["successCodes"] = []any{float64(0)}
			},
			want: "exit codes",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			command := validCommand()
			item.mutate(command)
			_, err := AdmitWithVocabulary(command, validVocabulary())
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("expected %q, got %v", item.want, err)
			}
		})
	}
}

func TestAdmitVocabularyRejectsUnknownPolicyFields(t *testing.T) {
	raw := validVocabularyRaw()
	raw["trustedProducerPolicy"] = "github-actions"

	_, err := AdmitVocabulary(raw)
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("AdmitVocabulary() error = %v, want unsupported field rejection", err)
	}
}

func TestAdmitVocabularyRejectsNumericDrift(t *testing.T) {
	for _, value := range []any{float64(10000), json.Number("10000.5")} {
		t.Run("maxTimeout", func(t *testing.T) {
			raw := validVocabularyRaw()
			raw["maxTimeoutMs"] = value
			_, err := AdmitVocabulary(raw)
			if err == nil || !strings.Contains(err.Error(), "maxTimeoutMs") {
				t.Fatalf("AdmitVocabulary() error=%v, want maxTimeoutMs rejection", err)
			}
		})
	}
}

func TestPlanCommandsRejectsDuplicateIDs(t *testing.T) {
	command, err := AdmitWithVocabulary(validCommand(), validVocabulary())
	if err != nil {
		t.Fatalf("admit command: %v", err)
	}
	_, err = PlanCommands([]Command{command, command})
	if err == nil || !strings.Contains(err.Error(), "sorted and unique") {
		t.Fatalf("expected duplicate id failure, got %v", err)
	}
}

func validVocabulary() Vocabulary {
	raw := validVocabularyRaw()
	vocabulary, err := AdmitVocabulary(raw)
	if err != nil {
		panic(err)
	}
	return vocabulary
}

func validVocabularyRaw() map[string]any {
	return map[string]any{
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
	}
}

func validCommand() map[string]any {
	raw := map[string]any{
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
	}
	return raw
}
