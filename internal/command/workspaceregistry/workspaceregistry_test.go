package workspaceregistry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildAdmitsWorkspaceRegistryAndRejectsMissingScriptTarget(t *testing.T) {
	record, exitCode, err := Build(validWorkspaceRegistryInput())
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		encoded, _ := json.Marshal(record)
		t.Fatalf("Build() exit=%d record=%s, want passed", exitCode, string(encoded))
	}

	input := validWorkspaceRegistryInput()
	script := input["packages"].([]any)[0].(map[string]any)["scripts"].([]any)[0].(map[string]any)
	script["command"] = "bun run --filter @example/missing test"
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build() missing target error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() accepted missing script target: exit=%d state=%s", exitCode, record.State)
	}
	encoded, _ := json.Marshal(record)
	if !strings.Contains(string(encoded), "targets missing package @example/missing") {
		t.Fatalf("record missing target failure: %s", string(encoded))
	}
}

func TestBuildRejectsUnknownWorkspaceRegistryFields(t *testing.T) {
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
			name: "root",
			mutate: func(input map[string]any) {
				input["root"].(map[string]any)["ambientPolicy"] = true
			},
		},
		{
			name: "package",
			mutate: func(input map[string]any) {
				input["packages"].([]any)[0].(map[string]any)["ambientPolicy"] = true
			},
		},
		{
			name: "script policy",
			mutate: func(input map[string]any) {
				input["scriptPolicy"].(map[string]any)["ambientPolicy"] = true
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validWorkspaceRegistryInput()
			item.mutate(input)
			_, _, err := Build(input)
			if err == nil || !strings.Contains(err.Error(), "unsupported field") {
				t.Fatalf("Build() error=%v, want unsupported field", err)
			}
		})
	}
}

func TestBuildRejectsSecretLikeWorkspaceScriptCommand(t *testing.T) {
	input := validWorkspaceRegistryInput()
	input["root"].(map[string]any)["scripts"].([]any)[0].(map[string]any)["command"] = "Authorization: Bearer abcdefghijklmnop"

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "secret-like values") {
		t.Fatalf("Build() error=%v, want secret-like package script rejection", err)
	}
}

func TestBuildRejectsSecretLikeExpectedSnippetFailureMessage(t *testing.T) {
	input := validWorkspaceRegistryInput()
	input["lockfilePolicy"] = map[string]any{
		"lockfileText": "lockfile",
		"expectedSnippets": []any{
			map[string]any{
				"failureMessage": "token=ghp_secretvalue",
				"snippet":        "lockfile",
			},
		},
	}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "secret-like values") {
		t.Fatalf("Build() error=%v, want secret-like diagnostic message rejection", err)
	}
}

func validWorkspaceRegistryInput() map[string]any {
	return map[string]any{
		"schemaVersion":     json.Number("1"),
		"knownPackageNames": []any{"@example/alpha"},
		"nonClaims":         []any{"Workspace registry test input does not execute scripts."},
		"root": map[string]any{
			"name":           "example-root",
			"dependencyRefs": []any{},
			"scripts": []any{
				map[string]any{"name": "quality", "command": "bun run test"},
			},
		},
		"packages": []any{
			map[string]any{
				"name":           "@example/alpha",
				"dirName":        "alpha",
				"dependencyRefs": []any{},
				"scripts": []any{
					map[string]any{"name": "test", "command": "bun run --filter @example/alpha test"},
				},
			},
		},
		"scriptPolicy": map[string]any{
			"admittedRootScriptNames":    []any{"quality"},
			"exactRootScripts":           []any{},
			"requiredPackageScriptNames": []any{"test"},
			"requiredRootScriptNames":    []any{},
			"selfTargetOptionNames":      []any{"--package"},
			"targetNamePrefixes":         []any{"@example/"},
			"targetOptionNames":          []any{"--filter"},
		},
		"dependencyPolicy": nil,
		"lockfilePolicy":   nil,
	}
}
