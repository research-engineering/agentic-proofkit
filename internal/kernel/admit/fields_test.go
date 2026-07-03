package admit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRuleIDRejectsUnstableIdentity(t *testing.T) {
	t.Parallel()

	if _, err := RuleID("proofkit.rule.2026-06-20", "rule id"); err == nil {
		t.Fatal("expected timestamp-like rule id rejection")
	}
	if _, err := RuleID("ghp_secretvalue", "rule id"); err == nil {
		t.Fatal("expected secret-like rule id rejection")
	}
	if _, err := RuleID("proofkit.rule.valid_id", "rule id"); err != nil {
		t.Fatalf("expected stable rule id: %v", err)
	}
}

func TestNonEmptyTextRejectsSecretLikeDiagnostics(t *testing.T) {
	t.Parallel()

	if _, err := NonEmptyText("Authorization: Bearer abcdefghijklmnop", "diagnostic"); err == nil {
		t.Fatal("expected secret-like diagnostic rejection")
	}
	if _, err := NonEmptyText("caller-provided evidence only", "diagnostic"); err != nil {
		t.Fatalf("expected non-secret diagnostic text: %v", err)
	}
}

func TestRedactDiagnosticValueRemovesSensitiveAndUnsafeSubstrings(t *testing.T) {
	t.Parallel()

	diagnostic := "open proofkit/ghp_secretvalue/input.json:\n" + strings.Repeat("x", 600)
	redacted := RedactDiagnosticValue(diagnostic)
	if strings.Contains(redacted, "ghp_secretvalue") {
		t.Fatalf("RedactDiagnosticValue leaked secret-shaped token: %q", redacted)
	}
	if !strings.Contains(redacted, "<redacted-secret-like-value>") {
		t.Fatalf("RedactDiagnosticValue(%q) = %q, want secret placeholder", diagnostic, redacted)
	}
	if !strings.Contains(redacted, "<redacted-control-rune>") {
		t.Fatalf("RedactDiagnosticValue(%q) = %q, want control placeholder", diagnostic, redacted)
	}
	if !strings.Contains(redacted, "<truncated-diagnostic>") {
		t.Fatalf("RedactDiagnosticValue(%q) = %q, want truncation marker", diagnostic, redacted)
	}
}

func TestSortedTextEnforcesUniquenessAndNonEmptyPolicy(t *testing.T) {
	t.Parallel()

	values, err := SortedText([]string{"b", "a"}, "refs", false)
	if err != nil {
		t.Fatalf("expected sortable unique refs: %v", err)
	}
	if strings.Join(values, ",") != "a,b" {
		t.Fatalf("expected sorted refs, got %q", strings.Join(values, ","))
	}
	if _, err := SortedText([]string{"a", "a"}, "refs", false); err == nil {
		t.Fatal("expected duplicate refs rejection")
	}
	if _, err := SortedText([]string{}, "refs", false); err == nil {
		t.Fatal("expected empty refs rejection")
	}
}

func TestPreserveSortedTextRejectsCallerOrderingDrift(t *testing.T) {
	t.Parallel()

	if _, err := PreserveSortedText([]string{"b", "a"}, "refs", false); err == nil {
		t.Fatal("expected caller ordering drift rejection")
	}
	values, err := PreserveSortedText([]string{"a", "b"}, "refs", false)
	if err != nil {
		t.Fatalf("expected sorted refs: %v", err)
	}
	if strings.Join(values, ",") != "a,b" {
		t.Fatalf("expected preserved sorted refs, got %q", strings.Join(values, ","))
	}
}

func TestSafeRepoRelativePathRejectsEscapesAndNormalization(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"..", "../outside.md", "docs//INDEX.md", "/absolute.md", `docs\\INDEX.md`, ".", "C:/outside/report.json", "file:docs/report.json", "https://example.test/report.json", "packages/ghp_secretvalue/src/index.ts", "docs/index\n.md", "docs/index\r.md", "docs/index\t.md", "docs/index\x7f.md"} {
		if _, err := SafeRepoRelativePath(value, "path"); err == nil {
			t.Fatalf("expected unsafe path rejection for %q", value)
		}
	}
	if value, err := SafeRepoRelativePath("docs/INDEX.md", "path"); err != nil || value != "docs/INDEX.md" {
		t.Fatalf("expected stable repo-relative path, got %q %v", value, err)
	}
}

func TestJSONNumberEqualsRequiresDecodedJSONNumber(t *testing.T) {
	t.Parallel()

	if JSONNumberEquals(float64(1), 1) {
		t.Fatal("expected non-json.Number input to be rejected")
	}
	if !JSONNumberEquals(json.Number("1"), 1) {
		t.Fatal("expected matching json.Number")
	}
	if JSONNumberEquals(json.Number("1.5"), 1) {
		t.Fatal("expected non-integer json.Number to be rejected")
	}
}

func TestPositiveIntegerRequiresDecodedPositiveInteger(t *testing.T) {
	t.Parallel()

	if value, err := PositiveInteger(json.Number("2"), "limit"); err != nil || value != 2 {
		t.Fatalf("expected positive integer, got %d %v", value, err)
	}
	for _, raw := range []any{json.Number("0"), json.Number("-1"), json.Number("1.5"), float64(1)} {
		if _, err := PositiveInteger(raw, "limit"); err == nil {
			t.Fatalf("expected positive integer rejection for %#v", raw)
		}
	}
}

func TestKnownKeysRedactsSecretLikeUnsupportedFieldNames(t *testing.T) {
	err := KnownKeys(
		map[string]any{"api_key=ghp_secretvalue": true, "safeExtra": true},
		[]string{"allowed"},
		"test input",
	)
	if err == nil {
		t.Fatalf("KnownKeys() error = nil, want unsupported field error")
	}
	message := err.Error()
	if strings.Contains(message, "ghp_secretvalue") || strings.Contains(message, "api_key=") {
		t.Fatalf("KnownKeys() error leaked secret-like field name: %q", message)
	}
	if !strings.Contains(message, "<redacted-unsupported-field-001>") || !strings.Contains(message, "safeExtra") {
		t.Fatalf("KnownKeys() error = %q, want redacted secret-like field and safe field label", message)
	}
}

func TestDisplayOnlyCommandTextRejectsShellControlTokens(t *testing.T) {
	for _, command := range []string{"go test ./... && curl example.test", "bun test | tee out.log", "npm test; rm -rf dist"} {
		if _, err := DisplayOnlyCommandText(command, "command"); err == nil {
			t.Fatalf("DisplayOnlyCommandText(%q) error = nil, want shell control token rejection", command)
		}
	}
	if got, err := DisplayOnlyCommandText("go test ./...", "command"); err != nil || got != "go test ./..." {
		t.Fatalf("DisplayOnlyCommandText(valid) = %q, %v", got, err)
	}
}
