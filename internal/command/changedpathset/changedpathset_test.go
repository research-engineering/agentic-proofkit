package changedpathset

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

func TestAgentEnvelopeContextPointersResolveAgainstCanonicalOutput(t *testing.T) {
	result, err := Build(map[string]any{
		"schemaVersion":       json.Number("1"),
		"reportId":            "proofkit.test.changed-path-set",
		"preexistingFailures": []any{},
		"nonClaims":           []any{"Changed-path test input does not prove git diff freshness."},
		"sources":             []any{map[string]any{"sourceId": "git", "paths": []any{"a.ts"}}},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	output := result.JSONValue()
	envelope := AgentEnvelope(result)
	for _, value := range envelope["contextRefs"].([]any) {
		ref := value.(map[string]any)
		selector, _ := ref["selector"].(string)
		if !strings.HasPrefix(selector, "/") {
			continue
		}
		if _, err := jsonpointer.Select(output, selector); err != nil {
			t.Fatalf("context ref %s has dangling selector %s: %v", ref["refId"], selector, err)
		}
	}
}

func TestBuildDeduplicatesAndFailsClosedOnInvalidPaths(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.020996495977209692976965486603091189537178619363476268911749132800454063351641")
	result, err := Build(map[string]any{
		"schemaVersion":       json.Number("1"),
		"reportId":            "proofkit.test.changed-path-set",
		"preexistingFailures": []any{},
		"nonClaims":           []any{"Changed-path test input does not prove git diff freshness."},
		"sources": []any{
			map[string]any{"sourceId": "git", "paths": []any{"b.ts", "a.ts", "a.ts"}},
			map[string]any{"sourceId": "override", "paths": []any{"b.ts", "c.ts"}},
		},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if result.ExitCode != 0 || result.Report.State != "passed" {
		t.Fatalf("Build() exitCode=%d state=%s, want passed", result.ExitCode, result.Report.State)
	}
	if got := strings.Join(result.ChangedPaths, ","); got != "a.ts,b.ts,c.ts" {
		t.Fatalf("ChangedPaths=%q, want sorted unique paths", got)
	}
	if len(result.DuplicatePaths) != 4 {
		t.Fatalf("DuplicatePaths=%d, want input and cross-source duplicate diagnostics", len(result.DuplicatePaths))
	}
	if !containsAnyString(result.Report.NonClaims, "Changed path set reports do not run git, inspect the filesystem, or discover changed paths.") {
		t.Fatalf("NonClaims missing command-owned boundary denial: %#v", result.Report.NonClaims)
	}

	result, err = Build(map[string]any{
		"schemaVersion":       json.Number("1"),
		"reportId":            "proofkit.test.changed-path-set",
		"preexistingFailures": []any{},
		"nonClaims":           []any{"Changed-path test input does not prove git diff freshness."},
		"sources": []any{
			map[string]any{"sourceId": "git", "paths": []any{"../password=supersecret"}},
		},
	})
	if err != nil {
		t.Fatalf("Build() invalid path error = %v", err)
	}
	encoded, _ := json.Marshal(result.Report)
	if result.ExitCode == 0 || result.Report.State != "failed" || !strings.Contains(string(encoded), "redacted-path:") {
		t.Fatalf("Build() did not fail closed with redacted diagnostics: exitCode=%d report=%s", result.ExitCode, string(encoded))
	}
	if strings.Contains(string(encoded), "supersecret") || strings.Contains(string(encoded), "password=") {
		t.Fatalf("Build() leaked secret-shaped invalid path diagnostic: %s", string(encoded))
	}
}

func TestBuildRejectsSecretLikeReportVisibleText(t *testing.T) {
	secret := "sk-proj-abcdefghijklmnop"
	result, err := Build(map[string]any{
		"schemaVersion":       json.Number("1"),
		"reportId":            "proofkit.test.changed-path-set",
		"preexistingFailures": []any{},
		"nonClaims":           []any{secret},
		"sources":             []any{map[string]any{"sourceId": "git", "paths": []any{"a.ts"}}},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	encoded, _ := json.Marshal(result.Report)
	if result.ExitCode == 0 || result.Report.State != "failed" {
		t.Fatalf("Build() exitCode=%d state=%s, want failed", result.ExitCode, result.Report.State)
	}
	if strings.Contains(string(encoded), "abcdefghijklmnop") {
		t.Fatalf("Build() leaked secret text in report: %s", string(encoded))
	}

	result, err = Build(map[string]any{
		"schemaVersion":       json.Number("1"),
		"reportId":            "proofkit.test.changed-path-set",
		"preexistingFailures": []any{"https://user:password@example.invalid"},
		"nonClaims":           []any{"Changed-path test input does not prove git diff freshness."},
		"sources":             []any{map[string]any{"sourceId": "git", "paths": []any{"a.ts"}}},
	})
	if err != nil {
		t.Fatalf("Build() second error = %v", err)
	}
	encoded, _ = json.Marshal(result.Report)
	if result.ExitCode == 0 || result.Report.State != "failed" {
		t.Fatalf("Build() second exitCode=%d state=%s, want failed", result.ExitCode, result.Report.State)
	}
	if strings.Contains(string(encoded), "password") || strings.Contains(string(encoded), "example.invalid") {
		t.Fatalf("Build() leaked URL credential text in report: %s", string(encoded))
	}
}

func containsAnyString(values []any, want string) bool {
	for _, value := range values {
		if text, ok := value.(string); ok && text == want {
			return true
		}
	}
	return false
}
