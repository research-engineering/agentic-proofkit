package secretscan

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.secret-scan"

var fileStates = map[string]struct{}{
	"missing": {},
	"present": {},
}

type input struct {
	Files     []fileRecord
	NonClaims []string
	ReportID  string
}

type fileRecord struct {
	ContentBase64 *string
	Path          string
	State         string
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	findings := []map[string]any{}
	checkedCount := 0
	missingSkippedCount := 0
	for _, file := range input.Files {
		if file.State == "missing" {
			missingSkippedCount++
			continue
		}
		if file.ContentBase64 == nil {
			return report.Record{}, 1, fmt.Errorf("secret scan file %s is present and must include contentBase64", file.Path)
		}
		content, err := base64.StdEncoding.DecodeString(*file.ContentBase64)
		if err != nil {
			return report.Record{}, 1, fmt.Errorf("secret scan file %s contentBase64 must be valid base64", file.Path)
		}
		checkedCount++
		findings = append(findings, scanFile(file.Path, string(content))...)
	}
	sort.Slice(findings, func(i int, j int) bool {
		left := findings[i]["path"].(string)
		right := findings[j]["path"].(string)
		if left != right {
			return left < right
		}
		return findings[i]["line"].(int) < findings[j]["line"].(int)
	})
	state := "passed"
	exitCode := 0
	if len(findings) > 0 {
		state = "failed"
		exitCode = 1
	}
	nonClaims := append([]string{
		"Secret scan checks caller-provided file inventory only.",
		"Secret scan does not discover git state, traverse repository files, validate credential liveness, replace provider secret scanning, approve merge, release, rollout, or production readiness.",
	}, input.NonClaims...)
	sort.Strings(nonClaims)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.ReportID,
		State:         state,
		Summary: map[string]any{
			"checkedFileCount":        checkedCount,
			"findingCount":            len(findings),
			"inputFileCount":          len(input.Files),
			"missingSkippedFileCount": missingSkippedCount,
		},
		Diagnostics: []report.Diagnostic{
			{Key: "findings", Value: mapsToAny(findings)},
		},
		RuleResults: []report.RuleResult{
			{
				RuleID:  "proofkit.secret-scan.explicit-inventory",
				Status:  state,
				Message: ruleMessage(state),
				Diagnostics: []report.Diagnostic{
					{Key: "findingCount", Value: len(findings)},
				},
			},
		},
		NonClaims: stringsToAny(nonClaims),
	}
	return record, exitCode, nil
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("secret scan input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"files", "nonClaims", "reportId", "schemaVersion"}, "secret scan input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("secret scan input schemaVersion must be 1")
	}
	reportID, err := admit.RuleID(record["reportId"], "secret scan reportId")
	if err != nil {
		return input{}, err
	}
	files, err := admitFiles(record["files"])
	if err != nil {
		return input{}, err
	}
	nonClaims, err := admit.SortedTextArray(record["nonClaims"], "secret scan nonClaims", true)
	if err != nil {
		return input{}, err
	}
	return input{Files: files, NonClaims: nonClaims, ReportID: reportID}, nil
}

func admitFiles(raw any) ([]fileRecord, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("secret scan files must be an array")
	}
	files := make([]fileRecord, 0, len(values))
	paths := make([]string, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("secret scan files[%d] must be an object", index)
		}
		if err := admit.KnownKeys(record, []string{"contentBase64", "path", "state"}, fmt.Sprintf("secret scan files[%d]", index)); err != nil {
			return nil, err
		}
		pathValue, ok := record["path"].(string)
		if !ok {
			return nil, fmt.Errorf("secret scan files[%d].path must be a repository-relative POSIX path", index)
		}
		pathValue, err := admit.SafeRepoRelativePath(pathValue, fmt.Sprintf("secret scan files[%d].path", index))
		if err != nil {
			return nil, err
		}
		state, err := admit.Enum(record["state"], fileStates, fmt.Sprintf("secret scan files[%d].state", index))
		if err != nil {
			return nil, err
		}
		var contentBase64 *string
		if rawContent, exists := record["contentBase64"]; exists {
			content, ok := rawContent.(string)
			if !ok {
				return nil, fmt.Errorf("secret scan files[%d].contentBase64 must be text", index)
			}
			contentBase64 = &content
		}
		if state == "missing" && contentBase64 != nil {
			return nil, fmt.Errorf("secret scan files[%d] missing files must not carry contentBase64", index)
		}
		files = append(files, fileRecord{ContentBase64: contentBase64, Path: pathValue, State: state})
		paths = append(paths, pathValue)
	}
	if _, err := admit.PreserveSortedText(paths, "secret scan file paths", true); err != nil {
		return nil, err
	}
	return files, nil
}

func scanFile(path string, content string) []map[string]any {
	lines := strings.Split(content, "\n")
	findings := []map[string]any{}
	for index, line := range lines {
		if admit.ContainsSecretLikeValue(line) {
			findings = append(findings, map[string]any{
				"findingClass": "secret_like_value",
				"line":         index + 1,
				"path":         path,
			})
		}
	}
	return findings
}

func ruleMessage(state string) string {
	if state == "passed" {
		return "Caller-provided file inventory does not contain admitted secret-like text patterns."
	}
	return "Caller-provided file inventory contains secret-like text patterns."
}

func mapsToAny(values []map[string]any) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func stringsToAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
