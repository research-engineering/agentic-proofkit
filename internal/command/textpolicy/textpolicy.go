package textpolicy

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.text-policy"

var fileStates = map[string]struct{}{
	"missing": {},
	"present": {},
}

type Input struct {
	Files     []FileRecord
	NonClaims []string
	Policy    Policy
	ReportID  string
}

type FileRecord struct {
	ContentBase64 *string
	Path          string
	State         string
}

type Policy struct {
	AllowTab                 bool
	AsciiOnly                bool
	BinarySuffixes           []string
	RejectTrailingWhitespace bool
	RequireFinalNewline      bool
}

type Result struct {
	BinarySkippedCount  int
	CheckedCount        int
	ExitCode            int
	Failures            []string
	MissingSkippedCount int
	Report              report.Record
}

func Build(raw any) (report.Record, int, error) {
	result, err := Evaluate(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	return result.Report, result.ExitCode, nil
}

func Evaluate(raw any) (Result, error) {
	input, err := admitInput(raw)
	if err != nil {
		return Result{}, err
	}
	failures := []string{}
	checkedCount := 0
	binarySkippedCount := 0
	missingSkippedCount := 0
	for _, file := range input.Files {
		if isBinaryCandidate(file.Path, input.Policy.BinarySuffixes) {
			binarySkippedCount++
			continue
		}
		if file.State == "missing" {
			missingSkippedCount++
			continue
		}
		if file.ContentBase64 == nil {
			failures = append(failures, fmt.Sprintf("%s: present text file is missing contentBase64", file.Path))
			continue
		}
		content, err := base64.StdEncoding.DecodeString(*file.ContentBase64)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: contentBase64 is not valid base64", file.Path))
			continue
		}
		fileFailures, checked := verifyFile(input.Policy, file.Path, content)
		if checked {
			checkedCount++
		}
		failures = append(failures, fileFailures...)
	}
	sort.Strings(failures)
	state := "passed"
	exitCode := 0
	if len(failures) > 0 {
		state = "failed"
		exitCode = 1
	}
	nonClaims := append([]string{
		"Text policy checks caller-provided file inventory only.",
		"Text policy does not discover git state, read repository files, own repository-specific documentation topology, decide proof freshness, approve merge, release, or rollout.",
	}, input.NonClaims...)
	sort.Strings(nonClaims)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.ReportID,
		State:         state,
		Summary: map[string]any{
			"admittedPolicy":          policySummary(input.Policy),
			"binarySkippedFileCount":  binarySkippedCount,
			"checkedTextFileCount":    checkedCount,
			"failureCount":            len(failures),
			"inputFileCount":          len(input.Files),
			"missingSkippedFileCount": missingSkippedCount,
		},
		Diagnostics: []report.Diagnostic{
			{Key: "failures", Value: stringsToAny(failures)},
		},
		RuleResults: []report.RuleResult{
			{
				RuleID:  "proofkit.text-policy.admitted-policy",
				Status:  state,
				Message: ruleMessage(state),
				Diagnostics: []report.Diagnostic{
					{Key: "failureCount", Value: len(failures)},
				},
			},
		},
		NonClaims: stringsToAny(nonClaims),
	}
	return Result{
		BinarySkippedCount:  binarySkippedCount,
		CheckedCount:        checkedCount,
		ExitCode:            exitCode,
		Failures:            failures,
		MissingSkippedCount: missingSkippedCount,
		Report:              record,
	}, nil
}

func admitInput(raw any) (Input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Input{}, fmt.Errorf("text policy input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"files", "nonClaims", "policy", "reportId", "schemaVersion"}, "text policy input"); err != nil {
		return Input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return Input{}, fmt.Errorf("text policy input schemaVersion must be 1")
	}
	reportID, err := admit.RuleID(record["reportId"], "text policy reportId")
	if err != nil {
		return Input{}, err
	}
	policy, err := admitPolicy(record["policy"])
	if err != nil {
		return Input{}, err
	}
	files, err := admitFiles(record["files"])
	if err != nil {
		return Input{}, err
	}
	nonClaims, err := admit.SortedTextArray(record["nonClaims"], "text policy nonClaims", true)
	if err != nil {
		return Input{}, err
	}
	return Input{Files: files, NonClaims: nonClaims, Policy: policy, ReportID: reportID}, nil
}

func admitPolicy(raw any) (Policy, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Policy{}, fmt.Errorf("text policy policy must be an object")
	}
	if err := admit.KnownKeys(record, []string{"allowTab", "asciiOnly", "binarySuffixes", "rejectTrailingWhitespace", "requireFinalNewline"}, "text policy policy"); err != nil {
		return Policy{}, err
	}
	allowTab, err := boolField(record["allowTab"], "text policy allowTab")
	if err != nil {
		return Policy{}, err
	}
	asciiOnly, err := boolField(record["asciiOnly"], "text policy asciiOnly")
	if err != nil {
		return Policy{}, err
	}
	rejectTrailingWhitespace, err := boolField(record["rejectTrailingWhitespace"], "text policy rejectTrailingWhitespace")
	if err != nil {
		return Policy{}, err
	}
	requireFinalNewline, err := boolField(record["requireFinalNewline"], "text policy requireFinalNewline")
	if err != nil {
		return Policy{}, err
	}
	suffixes, err := admit.PreserveSortedTextArray(record["binarySuffixes"], "text policy binarySuffixes", true)
	if err != nil {
		return Policy{}, err
	}
	for _, suffix := range suffixes {
		if !strings.HasPrefix(suffix, ".") || strings.ToLower(suffix) != suffix || strings.ContainsAny(suffix, `/\`) {
			return Policy{}, fmt.Errorf("text policy binarySuffixes must be lowercase file suffixes")
		}
	}
	return Policy{
		AllowTab:                 allowTab,
		AsciiOnly:                asciiOnly,
		BinarySuffixes:           suffixes,
		RejectTrailingWhitespace: rejectTrailingWhitespace,
		RequireFinalNewline:      requireFinalNewline,
	}, nil
}

func admitFiles(raw any) ([]FileRecord, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("text policy files must be an array")
	}
	files := make([]FileRecord, 0, len(values))
	paths := make([]string, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("text policy files[%d] must be an object", index)
		}
		if err := admit.KnownKeys(record, []string{"contentBase64", "path", "state"}, fmt.Sprintf("text policy files[%d]", index)); err != nil {
			return nil, err
		}
		pathValue, ok := record["path"].(string)
		if !ok {
			return nil, fmt.Errorf("text policy files[%d].path must be a repository-relative POSIX path", index)
		}
		pathValue, err := admit.SafeRepoRelativePath(pathValue, fmt.Sprintf("text policy files[%d].path", index))
		if err != nil {
			return nil, err
		}
		state, err := admit.Enum(record["state"], fileStates, fmt.Sprintf("text policy files[%d].state", index))
		if err != nil {
			return nil, err
		}
		var contentBase64 *string
		if rawContent, exists := record["contentBase64"]; exists {
			content, ok := rawContent.(string)
			if !ok {
				return nil, fmt.Errorf("text policy files[%d].contentBase64 must be text", index)
			}
			contentBase64 = &content
		}
		if state == "missing" && contentBase64 != nil {
			return nil, fmt.Errorf("text policy files[%d] missing files must not carry contentBase64", index)
		}
		files = append(files, FileRecord{ContentBase64: contentBase64, Path: pathValue, State: state})
		paths = append(paths, pathValue)
	}
	if _, err := admit.PreserveSortedText(paths, "text policy file paths", true); err != nil {
		return nil, err
	}
	return files, nil
}

func boolField(raw any, context string) (bool, error) {
	value, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be boolean", context)
	}
	return value, nil
}

func isBinaryCandidate(path string, suffixes []string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	for _, suffix := range suffixes {
		if extension == suffix {
			return true
		}
	}
	return false
}

func verifyFile(policy Policy, path string, data []byte) ([]string, bool) {
	failures := []string{}
	if !utf8.Valid(data) {
		return []string{fmt.Sprintf("%s: not valid UTF-8", path)}, false
	}
	if policy.RequireFinalNewline && len(data) > 0 && data[len(data)-1] != '\n' {
		failures = append(failures, fmt.Sprintf("%s: missing final newline", path))
	}
	if policy.AsciiOnly {
		line := 1
		column := 1
		for _, value := range string(data) {
			switch value {
			case '\n':
				line++
				column = 1
				continue
			case '\t':
				if policy.AllowTab {
					column++
					continue
				}
			}
			if value < 32 || value > 126 {
				failures = append(failures, fmt.Sprintf("%s:%d:%d: non-ASCII U+%04X", path, line, column, value))
				return failures, true
			}
			column++
		}
	}
	if policy.RejectTrailingWhitespace {
		for lineIndex, lineData := range strings.Split(string(data), "\n") {
			if strings.HasSuffix(lineData, " ") || strings.HasSuffix(lineData, "\t") {
				failures = append(failures, fmt.Sprintf("%s:%d: trailing whitespace", path, lineIndex+1))
				return failures, true
			}
		}
	}
	return failures, true
}

func ruleMessage(state string) string {
	if state == "passed" {
		return "Caller-provided text files satisfy the admitted text policy."
	}
	return "Caller-provided text files violate the admitted text policy."
}

func policySummary(policy Policy) map[string]any {
	suffixes := make([]any, 0, len(policy.BinarySuffixes))
	for _, suffix := range policy.BinarySuffixes {
		suffixes = append(suffixes, suffix)
	}
	return map[string]any{
		"allowTab":                 policy.AllowTab,
		"asciiOnly":                policy.AsciiOnly,
		"binarySuffixes":           suffixes,
		"rejectTrailingWhitespace": policy.RejectTrailingWhitespace,
		"requireFinalNewline":      policy.RequireFinalNewline,
	}
}

func stringsToAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
