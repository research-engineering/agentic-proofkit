package changedpathset

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildDeduplicatesAndFailsClosedOnInvalidPaths(t *testing.T) {
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
