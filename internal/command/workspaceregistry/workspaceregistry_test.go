package workspaceregistry

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildAdmitsWorkspaceRegistryAndRejectsMissingScriptTarget(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.063080661639755003031032251305144344878025724678482041048084098938166996025209")
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

// An absent or null admittedRootScriptNames leaves root scripts unrestricted;
// an explicit [] is an empty allowlist that refuses every root script.
func TestAdmittedRootScriptNamesAbsenceIsNotAnEmptyAllowlist(t *testing.T) {
	for _, test := range []struct {
		name       string
		allowlist  any
		omitted    bool
		unexpected bool
	}{
		{name: "omitted", omitted: true},
		{name: "null", allowlist: nil},
		{name: "empty", allowlist: []any{}, unexpected: true},
		{name: "admitting", allowlist: []any{"quality"}},
		{name: "not admitting", allowlist: []any{"other"}, unexpected: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := validWorkspaceRegistryInput()
			policy := input["scriptPolicy"].(map[string]any)
			if test.omitted {
				delete(policy, "admittedRootScriptNames")
			} else {
				policy["admittedRootScriptNames"] = test.allowlist
			}
			record, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() error=%v", err)
			}
			var rootScripts *report.RuleResult
			for index := range record.RuleResults {
				if record.RuleResults[index].RuleID == rootScriptsRuleID {
					rootScripts = &record.RuleResults[index]
				}
			}
			encoded, _ := json.Marshal(record)
			if rootScripts == nil {
				t.Fatalf("root script rule is absent: %s", encoded)
			}
			refused := strings.Contains(string(encoded), "root package.json has unexpected script quality")
			if refused != test.unexpected || (exitCode != 0) != test.unexpected || (rootScripts.Status == "failed") != test.unexpected {
				t.Fatalf("exit=%d status=%s unexpected=%v, want unexpected=%v: %s", exitCode, rootScripts.Status, refused, test.unexpected, encoded)
			}
		})
	}
}
