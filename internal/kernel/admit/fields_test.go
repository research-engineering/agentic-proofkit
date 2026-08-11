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
	if _, err := RuleID("proofkit."+strings.Repeat("a", maxRuleIDBytes), "rule id"); err == nil {
		t.Fatal("expected oversized rule id rejection")
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

func TestLowercaseSHA256AdmitsOnlyCanonicalHexDigest(t *testing.T) {
	t.Parallel()

	if value, err := LowercaseSHA256(strings.Repeat("a", 64), "sha"); err != nil || value != strings.Repeat("a", 64) {
		t.Fatalf("expected canonical sha256 admission, got %q %v", value, err)
	}
	for _, value := range []any{
		strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("a", 64),
		strings.Repeat("a", 63),
		strings.Repeat("g", 64),
	} {
		if _, err := LowercaseSHA256(value, "sha"); err == nil {
			t.Fatalf("expected sha256 rejection for %#v", value)
		}
	}
}

func TestContainsSecretLikeValueRecognizesHyphenatedAndPasswdLabels(t *testing.T) {
	t.Parallel()

	for _, fixture := range ReportVisibleRedactionFixtures() {
		if !ContainsSecretLikeValue(fixture.Input) {
			t.Fatalf("ContainsSecretLikeValue(%s=%q) = false, want true", fixture.Name, fixture.Input)
		}
	}
	if ContainsSecretLikeValue("credentialClass=github-token") {
		t.Fatal("ContainsSecretLikeValue flagged a non-secret credential class label")
	}
}

func TestSafeRepoRelativePathUsesCompleteSecretTaxonomy(t *testing.T) {
	t.Parallel()

	for _, fixture := range ReportVisibleRedactionFixtures() {
		path := "artifacts/run-" + fixture.Input + ".log"
		if _, err := SafeRepoRelativePath(path, "report-visible path"); err == nil {
			t.Fatalf("SafeRepoRelativePath admitted embedded %s token", fixture.Name)
		}
	}
	if path, err := SafeRepoRelativePath("artifacts/run-proofkit-check.log", "report-visible path"); err != nil || path != "artifacts/run-proofkit-check.log" {
		t.Fatalf("SafeRepoRelativePath rejected benign path: %q %v", path, err)
	}
}

func TestSortedTextOwnersAdmitCanonicalContentBeforeOrdering(t *testing.T) {
	t.Parallel()

	if _, err := PreserveSortedText([]string{" "}, "nonClaims", false); err == nil {
		t.Fatal("PreserveSortedText admitted blank typed text")
	}
	if _, err := PreserveSortedText([]string{"sk-proj-abcdefghijklmnop"}, "nonClaims", false); err == nil {
		t.Fatal("PreserveSortedText admitted secret-shaped typed text")
	}
	if got, err := NormalizeSortedText([]string{" b ", "a"}, "labels", false); err != nil || strings.Join(got, ",") != "a,b" {
		t.Fatalf("NormalizeSortedText()=%v error=%v, want canonical a,b", got, err)
	}
}

func TestPreserveSortedPathsUsesPathAdmissionWithoutProseFalsePositives(t *testing.T) {
	t.Parallel()

	paths := []string{"docs/features/ai-risk-escalation.md", "proofkit/contracts.json"}
	if got, err := PreserveSortedPaths(paths, "paths", false); err != nil || strings.Join(got, ",") != strings.Join(paths, ",") {
		t.Fatalf("PreserveSortedPaths()=%v error=%v, want canonical paths", got, err)
	}
	if _, err := PreserveSortedPaths([]string{"artifacts/run-ghp_12345678901234567890.log"}, "paths", false); err == nil {
		t.Fatal("PreserveSortedPaths admitted a secret-shaped path")
	}
	unsorted := []string{"proofkit/contracts.json", "docs/features/ai-risk-escalation.md"}
	if got, err := NormalizeSortedPaths(unsorted, "paths", false); err != nil || strings.Join(got, ",") != strings.Join(paths, ",") {
		t.Fatalf("NormalizeSortedPaths()=%v error=%v, want sorted canonical paths", got, err)
	}
	if _, err := NormalizeSortedPaths([]string{"docs/same.md", "docs/same.md"}, "paths", false); err == nil {
		t.Fatal("NormalizeSortedPaths admitted duplicate paths")
	}
	pathPolicyOnly := "artifacts/run-sk-abcdefghij.log"
	if _, err := NonEmptyText(pathPolicyOnly, "prose"); err == nil {
		t.Fatal("test premise invalid: prose admission unexpectedly accepted the path-policy fixture")
	}
	for name, admitArray := range map[string]func(any, string, bool) ([]string, error){
		"normalize": NormalizeSortedPathArray,
		"preserve":  PreserveSortedPathArray,
	} {
		if got, err := admitArray([]any{pathPolicyOnly}, "paths", false); err != nil || len(got) != 1 || got[0] != pathPolicyOnly {
			t.Fatalf("%s path array=%v error=%v, want the canonical path-policy fixture", name, got, err)
		}
	}
}

func TestMergeNonClaimsPreservesRequiredClaimsAndRejectsSecretLikeCallerText(t *testing.T) {
	t.Parallel()

	merged, err := MergeNonClaims(
		[]string{"Command reports do not approve merge."},
		[]string{"Caller fixture does not execute tests.", "Command reports do not approve merge."},
		"test command",
	)
	if err != nil {
		t.Fatalf("MergeNonClaims() error = %v", err)
	}
	want := []string{"Caller fixture does not execute tests.", "Command reports do not approve merge."}
	if len(merged) != len(want) {
		t.Fatalf("MergeNonClaims()=%#v, want %#v", merged, want)
	}
	for index := range want {
		if merged[index] != want[index] {
			t.Fatalf("MergeNonClaims()=%#v, want %#v", merged, want)
		}
	}

	if _, err := MergeNonClaims([]string{"Command reports do not approve merge."}, []string{"Authorization: Bearer abcdefghijklmnop"}, "test command"); err == nil {
		t.Fatal("MergeNonClaims() accepted secret-like caller nonClaim")
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

	headerDiagnostic := "request failed: Authorization: Basic YWxpY2U6c2VjcmV0"
	headerRedacted := RedactDiagnosticValue(headerDiagnostic)
	if strings.Contains(headerRedacted, "YWxpY2U6c2VjcmV0") || strings.Contains(headerRedacted, "Basic") {
		t.Fatalf("RedactDiagnosticValue leaked authorization header value: %q", headerRedacted)
	}

	for _, fixture := range ReportVisibleRedactionFixtures() {
		redacted := RedactDiagnosticValue(fixture.Input)
		for _, needle := range fixture.SensitiveNeedles {
			if strings.Contains(redacted, needle) {
				t.Fatalf("RedactDiagnosticValue leaked %s needle %q in %q", fixture.Name, needle, redacted)
			}
		}
	}
}

func TestRedactStructuralTextPreservesLongStructureAndRedactsSensitiveTokens(t *testing.T) {
	t.Parallel()

	longToken := strings.Repeat("x", maxDiagnosticRunes+20)
	structural := RedactStructuralText(longToken + "\n" + "Authorization: Bearer abcdefghijklmnop")
	if strings.Contains(structural, "<truncated-diagnostic>") {
		t.Fatalf("RedactStructuralText truncated structural token: %q", structural)
	}
	if !strings.Contains(structural, longToken) {
		t.Fatalf("RedactStructuralText lost long structural token: %q", structural)
	}
	if !strings.Contains(structural, "<redacted-control-rune>") {
		t.Fatalf("RedactStructuralText(%q) = %q, want control placeholder", longToken, structural)
	}
	if !strings.Contains(structural, "<redacted-secret-like-value>") {
		t.Fatalf("RedactStructuralText(%q) = %q, want secret placeholder", longToken, structural)
	}
}

func TestNormalizeSortedTextEnforcesUniquenessWithoutAliasing(t *testing.T) {
	t.Parallel()

	input := []string{"b", "a"}
	values, err := NormalizeSortedText(input, "refs", false)
	if err != nil {
		t.Fatalf("expected sortable unique refs: %v", err)
	}
	if strings.Join(values, ",") != "a,b" {
		t.Fatalf("expected sorted refs, got %q", strings.Join(values, ","))
	}
	if strings.Join(input, ",") != "b,a" {
		t.Fatalf("input mutated to %q", strings.Join(input, ","))
	}
	if _, err := NormalizeSortedText([]string{"a", "a"}, "refs", false); err == nil {
		t.Fatal("expected duplicate refs rejection")
	}
	if _, err := NormalizeSortedText([]string{}, "refs", false); err == nil {
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

	for _, value := range []string{"..", "../outside.md", "docs//INDEX.md", "/absolute.md", `docs\\INDEX.md`, ".", "C:/outside/report.json", "file:docs/report.json", "https://example.test/report.json", "packages/ghp_secretvalue/src/index.ts", "artifacts/run-ghp_ABCDEFGHI.log", "docs/api_key=abc123456789.md", "docs/sk-proj-abcdefghijklmnop.md", "docs/index\n.md", "docs/index\r.md", "docs/index\t.md", "docs/index\x7f.md"} {
		if _, err := SafeRepoRelativePath(value, "path"); err == nil {
			t.Fatalf("expected unsafe path rejection for %q", value)
		}
	}
	for _, path := range []string{"docs/INDEX.md", "docs/risk-escalation.md", "docs/ai-risk-escalation.md", "docs/secrets-incident-prevention.md", "docs/api-key-rotation.md", "docs/sk-project-key.md"} {
		if value, err := SafeRepoRelativePath(path, "path"); err != nil || value != path {
			t.Fatalf("expected stable repo-relative path for %q, got %q %v", path, value, err)
		}
	}
}

func TestSHA256RefAdmitsOneCanonicalRepresentation(t *testing.T) {
	t.Parallel()
	digest := strings.Repeat("a", 64)
	if value, err := SHA256Ref("sha256:"+digest, "digest"); err != nil || value != "sha256:"+digest {
		t.Fatalf("SHA256Ref() value=%q error=%v", value, err)
	}
	if value, err := SHA256HexRef(digest, "digest"); err != nil || value != "sha256:"+digest {
		t.Fatalf("SHA256HexRef() value=%q error=%v", value, err)
	}
	for _, value := range []string{"sha256:" + strings.Repeat("a", 31) + " " + strings.Repeat("a", 32), "sha256:ABC", digest} {
		if _, err := SHA256Ref(value, "digest"); err == nil {
			t.Fatalf("SHA256Ref() accepted %q", value)
		}
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
	for _, value := range []json.Number{"+1", "01", "-0"} {
		if JSONNumberEquals(value, 1) || JSONNumberEquals(value, 0) {
			t.Fatalf("expected non-canonical JSON integer %q to be rejected", value)
		}
	}
}

func TestPositiveIntegerRequiresDecodedPositiveInteger(t *testing.T) {
	t.Parallel()

	if value, err := PositiveInteger(json.Number("2"), "limit"); err != nil || value != 2 {
		t.Fatalf("expected positive integer, got %d %v", value, err)
	}
	for _, raw := range []any{json.Number("0"), json.Number("-1"), json.Number("1.5"), json.Number("+1"), json.Number("01"), float64(1)} {
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

func TestStructuredSelectorSourcePathRejectsDrift(t *testing.T) {
	t.Parallel()

	if err := StructuredSelectorSourcePath("service/tests/auth_test.py::missing_header", "service/tests/auth_test.py", "selector"); err != nil {
		t.Fatalf("expected matching selector source path: %v", err)
	}
	if err := StructuredSelectorSourcePath("service/tests/other_test.py::missing_header", "service/tests/auth_test.py", "selector"); err == nil || !strings.Contains(err.Error(), "sourcePath must match selector path") {
		t.Fatalf("expected selector/sourcePath drift rejection, got %v", err)
	}
	if err := StructuredSelectorSourcePath("../auth_test.py::missing_header", "service/tests/auth_test.py", "selector"); err == nil || !strings.Contains(err.Error(), "must not escape the repository root") {
		t.Fatalf("expected unsafe selector path rejection, got %v", err)
	}
	if err := StructuredSelectorSourcePath("service/tests/auth_test.py::bad anchor", "service/tests/auth_test.py", "selector"); err == nil || !strings.Contains(err.Error(), "must be stable rule identifier text") {
		t.Fatalf("expected invalid selector anchor rejection, got %v", err)
	}
}
