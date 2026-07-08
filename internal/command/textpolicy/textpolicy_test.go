package textpolicy

import (
	"encoding/base64"
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"sort"
	"strings"
	"testing"
)

func TestEvaluatePreservesUTF8ASCIIWhitespaceAndBinaryFalsifiers(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.086855865554772597777106065642397508247799514617063694794143213323987594296092")
	result, err := Evaluate(validInput(map[string][]byte{
		"binary.ZIP":         []byte{0xff, 0xfe},
		"docs/empty.md":      {},
		"docs/missing.md":    nil,
		"docs/ok.md":         []byte("ok\n"),
		"docs/tab.md":        []byte("a\tb\n"),
		"src/bad-control.go": []byte("ok\x07\n"),
		"src/bad-utf8.go":    {0xff, 0xfe},
		"src/non-ascii.go":   []byte("caf\u00e9\n"),
		"src/no-newline.go":  []byte("package main"),
		"src/trailing.go":    []byte("package main \n"),
	}))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if result.ExitCode != 1 || result.Report.State != "failed" {
		t.Fatalf("Evaluate() exit=%d state=%s, want failed", result.ExitCode, result.Report.State)
	}
	assertFailure(t, result, "src/bad-control.go:1:3: non-ASCII U+0007")
	assertFailure(t, result, "src/bad-utf8.go: not valid UTF-8")
	assertFailure(t, result, "src/non-ascii.go:1:4: non-ASCII U+00E9")
	assertFailure(t, result, "src/no-newline.go: missing final newline")
	assertFailure(t, result, "src/trailing.go:1: trailing whitespace")
	if result.CheckedCount != 7 {
		t.Fatalf("checked count=%d, want 7", result.CheckedCount)
	}
	if result.BinarySkippedCount != 1 {
		t.Fatalf("binary skipped=%d, want 1", result.BinarySkippedCount)
	}
	if result.MissingSkippedCount != 1 {
		t.Fatalf("missing skipped=%d, want 1", result.MissingSkippedCount)
	}
}

func TestEvaluatePassesAdmittedTextInventory(t *testing.T) {
	result, err := Evaluate(validInput(map[string][]byte{
		"docs/empty.md": {},
		"docs/ok.md":    []byte("ok\n"),
		"docs/tab.md":   []byte("a\tb\n"),
		"image.png":     []byte{0xff, 0xfe},
	}))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if result.ExitCode != 0 || result.Report.State != "passed" {
		t.Fatalf("Evaluate() exit=%d state=%s, want passed", result.ExitCode, result.Report.State)
	}
	if result.CheckedCount != 3 || result.BinarySkippedCount != 1 || len(result.Failures) != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestEvaluateRejectsMalformedInventoryInsteadOfScanningRepository(t *testing.T) {
	cases := []struct {
		name  string
		input map[string]any
		want  string
	}{
		{
			name:  "unsorted files",
			input: unsortedFilesInput(),
			want:  "text policy file paths must be sorted and unique",
		},
		{
			name:  "unsafe path",
			input: validInput(map[string][]byte{"../outside.md": []byte("x\n")}),
			want:  "must not escape the repository root",
		},
		{
			name:  "missing file carries content",
			input: missingWithContentInput(),
			want:  "missing files must not carry contentBase64",
		},
		{
			name:  "unsorted suffixes",
			input: policyOverrideInput("binarySuffixes", []any{".zip", ".png"}),
			want:  "text policy binarySuffixes must be sorted and unique",
		},
		{
			name:  "uppercase suffix",
			input: policyOverrideInput("binarySuffixes", []any{".PNG"}),
			want:  "text policy binarySuffixes must be lowercase file suffixes",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, err := Evaluate(item.input)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Evaluate() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestBuildEmitsDeterministicReportWithoutFilesystemAuthority(t *testing.T) {
	report, exitCode, err := Build(validInput(map[string][]byte{"docs/ok.md": []byte("ok\n")}))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || report.ReportKind != reportKind || report.State != "passed" {
		t.Fatalf("Build() report=%#v exit=%d", report, exitCode)
	}
	if got := report.RuleResults[0].RuleID; got != "proofkit.text-policy.admitted-policy" {
		t.Fatalf("rule id=%s, want policy-neutral admitted-policy", got)
	}
	output, err := json.Marshal(report.JSONValue())
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(output), "repoRoot") {
		t.Fatalf("report must not claim repository scanning authority: %s", output)
	}
}

func TestBuildKeepsRuleIDTruthfulWhenPolicyIsRelaxed(t *testing.T) {
	input := validInput(map[string][]byte{"docs/no-newline.md": []byte("text")})
	policy := input["policy"].(map[string]any)
	policy["asciiOnly"] = false
	policy["rejectTrailingWhitespace"] = false
	policy["requireFinalNewline"] = false

	report, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || report.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want relaxed policy pass", exitCode, report.State)
	}
	if got := report.RuleResults[0].RuleID; strings.Contains(got, "ascii") || strings.Contains(got, "final-newline") {
		t.Fatalf("relaxed policy must not emit strict rule id: %s", got)
	}
	admittedPolicy, ok := report.Summary["admittedPolicy"].(map[string]any)
	if !ok {
		t.Fatalf("missing admittedPolicy summary: %#v", report.Summary)
	}
	if admittedPolicy["asciiOnly"] != false || admittedPolicy["requireFinalNewline"] != false {
		t.Fatalf("admittedPolicy summary does not reflect relaxed policy: %#v", admittedPolicy)
	}
}

func validInput(files map[string][]byte) map[string]any {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	fileRecords := make([]any, 0, len(paths))
	for _, path := range paths {
		data := files[path]
		if data == nil {
			fileRecords = append(fileRecords, map[string]any{
				"path":  path,
				"state": "missing",
			})
			continue
		}
		fileRecords = append(fileRecords, map[string]any{
			"contentBase64": base64.StdEncoding.EncodeToString(data),
			"path":          path,
			"state":         "present",
		})
	}
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"reportId":      "proofkit.text-policy.test",
		"nonClaims":     []any{"Test text policy input does not claim repository discovery."},
		"policy": map[string]any{
			"allowTab":                 true,
			"asciiOnly":                true,
			"binarySuffixes":           []any{".png", ".zip"},
			"rejectTrailingWhitespace": true,
			"requireFinalNewline":      true,
		},
		"files": fileRecords,
	}
}

func missingWithContentInput() map[string]any {
	input := validInput(map[string][]byte{"docs/missing.md": nil})
	file := input["files"].([]any)[0].(map[string]any)
	file["contentBase64"] = base64.StdEncoding.EncodeToString([]byte("unexpected\n"))
	return input
}

func policyOverrideInput(key string, value any) map[string]any {
	input := validInput(map[string][]byte{"docs/ok.md": []byte("ok\n")})
	policy := input["policy"].(map[string]any)
	policy[key] = value
	return input
}

func unsortedFilesInput() map[string]any {
	input := validInput(map[string][]byte{})
	input["files"] = []any{
		map[string]any{
			"contentBase64": base64.StdEncoding.EncodeToString([]byte("z\n")),
			"path":          "z.md",
			"state":         "present",
		},
		map[string]any{
			"contentBase64": base64.StdEncoding.EncodeToString([]byte("a\n")),
			"path":          "a.md",
			"state":         "present",
		},
	}
	return input
}

func assertFailure(t *testing.T, result Result, want string) {
	t.Helper()
	for _, failure := range result.Failures {
		if strings.Contains(failure, want) {
			return
		}
	}
	t.Fatalf("failures do not contain %q: %#v", want, result.Failures)
}
