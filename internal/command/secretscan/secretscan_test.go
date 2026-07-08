package secretscan

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildFindsSecretLikeTextWithoutLeakingValue(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.044627298880588177227751226258246473779575152087534439636266250802154512519866")
	const sentinel = "abc123456789"
	record, exitCode, err := Build(validInput(map[string][]byte{
		"docs/ok.md":       []byte("plain text\n"),
		"src/settings.env": []byte("api_key=" + sentinel + "\n"),
	}))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 1 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	if record.Summary["findingCount"] != 1 {
		t.Fatalf("findingCount=%#v, want 1", record.Summary["findingCount"])
	}
	encoded, err := json.Marshal(record.JSONValue())
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(encoded), sentinel) || strings.Contains(string(encoded), "api_key") {
		t.Fatalf("secret scan report leaked sensitive text: %s", encoded)
	}
	if !strings.Contains(string(encoded), "secret_like_value") {
		t.Fatalf("secret scan report did not classify finding: %s", encoded)
	}
}

func TestBuildPassesCleanExplicitInventory(t *testing.T) {
	record, exitCode, err := Build(validInput(map[string][]byte{
		"docs/ok.md": []byte("plain text\n"),
	}))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" || record.ReportKind != reportKind {
		t.Fatalf("Build() exit=%d record=%#v, want passed secret scan report", exitCode, record)
	}
}

func TestBuildSuppressesExplicitFindingAndRejectsStaleSuppression(t *testing.T) {
	input := validInput(map[string][]byte{
		".github/workflows/publish.yml": []byte("permissions:\n  id-token: write\n"),
	})
	input["suppressions"] = []any{map[string]any{
		"suppressionId": "proofkit.test.oidc_permission_fixture",
		"path":          ".github/workflows/publish.yml",
		"line":          json.Number("2"),
		"findingClass":  "secret_like_value",
		"reason":        "OIDC permission fixture text is expected in this caller-owned test inventory.",
	}}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}
	if record.Summary["findingCount"] != 1 || record.Summary["suppressedFindingCount"] != 1 || record.Summary["unsuppressedFindingCount"] != 0 {
		t.Fatalf("summary=%#v, want one suppressed finding and no unsuppressed findings", record.Summary)
	}
	encoded, err := json.Marshal(record.JSONValue())
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(encoded), "id-token: write") {
		t.Fatalf("suppressed report leaked matched line: %s", encoded)
	}

	input = validInput(map[string][]byte{
		".github/workflows/publish.yml": []byte("permissions:\n  contents: read\n"),
	})
	input["suppressions"] = []any{map[string]any{
		"suppressionId": "proofkit.test.stale_suppression",
		"path":          ".github/workflows/publish.yml",
		"line":          json.Number("2"),
		"findingClass":  "secret_like_value",
		"reason":        "This suppression should fail when no matching finding remains.",
	}}
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build(stale suppression) error = %v", err)
	}
	if exitCode != 1 || record.State != "failed" || record.Summary["unusedSuppressionCount"] != 1 {
		t.Fatalf("Build(stale suppression) exit=%d state=%s summary=%#v, want failed stale suppression", exitCode, record.State, record.Summary)
	}
}

func TestBuildAcceptsPathWithSecretLikeSyllable(t *testing.T) {
	_, exitCode, err := Build(validInput(map[string][]byte{
		"docs/features/ai-risk-escalation.md": []byte("safe text\n"),
	}))
	if err != nil {
		t.Fatalf("Build() rejected legitimate path component: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exit=%d, want clean path to pass", exitCode)
	}
}

func TestBuildRejectsMalformedInventoryInsteadOfScanningRepository(t *testing.T) {
	cases := []struct {
		name  string
		input map[string]any
		want  string
	}{
		{
			name:  "unsorted files",
			input: unsortedFilesInput(),
			want:  "secret scan file paths must be sorted and unique",
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
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, _, err := Build(item.input)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Build() error=%v, want %q", err, item.want)
			}
		})
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
		"reportId":      "proofkit.secret-scan.test",
		"nonClaims":     []any{"Test secret scan input does not claim repository discovery."},
		"files":         fileRecords,
	}
}

func missingWithContentInput() map[string]any {
	input := validInput(map[string][]byte{"docs/missing.md": nil})
	file := input["files"].([]any)[0].(map[string]any)
	file["contentBase64"] = base64.StdEncoding.EncodeToString([]byte("unexpected\n"))
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
