package secretscan

import (
	"encoding/base64"
	"encoding/json"
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
	Files        []fileRecord
	NonClaims    []string
	ReportID     string
	Suppressions []suppressionRecord
}

type fileRecord struct {
	ContentBase64 *string
	Path          string
	State         string
}

type findingRecord struct {
	FindingClass string
	Line         int
	Path         string
}

type suppressionRecord struct {
	FindingClass  string
	Line          int
	Path          string
	Reason        string
	SuppressionID string
}

type suppressedFindingRecord struct {
	findingRecord
	Reason        string
	SuppressionID string
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	findings := []findingRecord{}
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
	sortFindings(findings)
	unsuppressed, suppressed, unusedSuppressions := applySuppressions(findings, input.Suppressions)
	state := "passed"
	exitCode := 0
	if len(unsuppressed) > 0 || len(unusedSuppressions) > 0 {
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
			"checkedFileCount":         checkedCount,
			"findingCount":             len(findings),
			"inputFileCount":           len(input.Files),
			"missingSkippedFileCount":  missingSkippedCount,
			"suppressedFindingCount":   len(suppressed),
			"suppressionCount":         len(input.Suppressions),
			"unusedSuppressionCount":   len(unusedSuppressions),
			"unsuppressedFindingCount": len(unsuppressed),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "findings", Value: findingsToAny(unsuppressed)},
			{Key: "suppressedFindings", Value: suppressedFindingsToAny(suppressed)},
			{Key: "unusedSuppressions", Value: suppressionsToAny(unusedSuppressions)},
		},
		RuleResults: []report.RuleResult{
			{
				RuleID:  "proofkit.secret-scan.explicit-inventory",
				Status:  state,
				Message: ruleMessage(state),
				Diagnostics: []report.Diagnostic{
					{Key: "findingCount", Value: len(findings)},
					{Key: "suppressedFindingCount", Value: len(suppressed)},
					{Key: "unusedSuppressionCount", Value: len(unusedSuppressions)},
					{Key: "unsuppressedFindingCount", Value: len(unsuppressed)},
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
	if err := admit.KnownKeys(record, []string{"files", "nonClaims", "reportId", "schemaVersion", "suppressions"}, "secret scan input"); err != nil {
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
	suppressions, err := admitSuppressions(record["suppressions"])
	if err != nil {
		return input{}, err
	}
	return input{Files: files, NonClaims: nonClaims, ReportID: reportID, Suppressions: suppressions}, nil
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

func admitSuppressions(raw any) ([]suppressionRecord, error) {
	if raw == nil {
		return []suppressionRecord{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("secret scan suppressions must be an array")
	}
	result := make([]suppressionRecord, 0, len(values))
	seenIDs := map[string]struct{}{}
	seenKeys := map[string]struct{}{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("secret scan suppressions[%d] must be an object", index)
		}
		if err := admit.KnownKeys(record, []string{"findingClass", "line", "path", "reason", "suppressionId"}, fmt.Sprintf("secret scan suppressions[%d]", index)); err != nil {
			return nil, err
		}
		suppressionID, err := admit.RuleID(record["suppressionId"], fmt.Sprintf("secret scan suppressions[%d].suppressionId", index))
		if err != nil {
			return nil, err
		}
		if _, exists := seenIDs[suppressionID]; exists {
			return nil, fmt.Errorf("secret scan suppressionId must be unique")
		}
		seenIDs[suppressionID] = struct{}{}
		pathValue, ok := record["path"].(string)
		if !ok {
			return nil, fmt.Errorf("secret scan suppressions[%d].path must be a repository-relative POSIX path", index)
		}
		pathValue, err = admit.SafeRepoRelativePath(pathValue, fmt.Sprintf("secret scan suppressions[%d].path", index))
		if err != nil {
			return nil, err
		}
		findingClass, err := admit.Enum(record["findingClass"], map[string]struct{}{"secret_like_value": {}}, fmt.Sprintf("secret scan suppressions[%d].findingClass", index))
		if err != nil {
			return nil, err
		}
		line, err := positiveJSONInt(record["line"], fmt.Sprintf("secret scan suppressions[%d].line", index))
		if err != nil {
			return nil, err
		}
		reason, err := admit.NonEmptyText(record["reason"], fmt.Sprintf("secret scan suppressions[%d].reason", index))
		if err != nil {
			return nil, err
		}
		item := suppressionRecord{FindingClass: findingClass, Line: line, Path: pathValue, Reason: reason, SuppressionID: suppressionID}
		key := suppressionKey(item)
		if _, exists := seenKeys[key]; exists {
			return nil, fmt.Errorf("secret scan suppressions must not duplicate path, line, and findingClass")
		}
		seenKeys[key] = struct{}{}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].SuppressionID < result[right].SuppressionID
	})
	return result, nil
}

func positiveJSONInt(raw any, context string) (int, error) {
	number, ok := raw.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s must be a positive JSON integer", context)
	}
	value, err := number.Int64()
	if err != nil || value < 1 || int64(int(value)) != value {
		return 0, fmt.Errorf("%s must be a positive JSON integer", context)
	}
	return int(value), nil
}

func scanFile(path string, content string) []findingRecord {
	lines := strings.Split(content, "\n")
	findings := []findingRecord{}
	for index, line := range lines {
		if admit.ContainsSecretLikeValue(line) {
			findings = append(findings, findingRecord{FindingClass: "secret_like_value", Line: index + 1, Path: path})
		}
	}
	return findings
}

func applySuppressions(findings []findingRecord, suppressions []suppressionRecord) ([]findingRecord, []suppressedFindingRecord, []suppressionRecord) {
	byKey := map[string]suppressionRecord{}
	used := map[string]struct{}{}
	for _, suppression := range suppressions {
		byKey[suppressionKey(suppression)] = suppression
	}
	unsuppressed := []findingRecord{}
	suppressed := []suppressedFindingRecord{}
	for _, finding := range findings {
		suppression, ok := byKey[findingKey(finding)]
		if !ok {
			unsuppressed = append(unsuppressed, finding)
			continue
		}
		used[suppression.SuppressionID] = struct{}{}
		suppressed = append(suppressed, suppressedFindingRecord{findingRecord: finding, Reason: suppression.Reason, SuppressionID: suppression.SuppressionID})
	}
	unused := []suppressionRecord{}
	for _, suppression := range suppressions {
		if _, ok := used[suppression.SuppressionID]; !ok {
			unused = append(unused, suppression)
		}
	}
	sortFindings(unsuppressed)
	sort.Slice(suppressed, func(left int, right int) bool {
		return findingKey(suppressed[left].findingRecord) < findingKey(suppressed[right].findingRecord)
	})
	sort.Slice(unused, func(left int, right int) bool {
		return unused[left].SuppressionID < unused[right].SuppressionID
	})
	return unsuppressed, suppressed, unused
}

func findingKey(finding findingRecord) string {
	return fmt.Sprintf("%s\x00%09d\x00%s", finding.Path, finding.Line, finding.FindingClass)
}

func suppressionKey(suppression suppressionRecord) string {
	return fmt.Sprintf("%s\x00%09d\x00%s", suppression.Path, suppression.Line, suppression.FindingClass)
}

func sortFindings(findings []findingRecord) {
	sort.Slice(findings, func(i int, j int) bool {
		return findingKey(findings[i]) < findingKey(findings[j])
	})
}

func ruleMessage(state string) string {
	if state == "passed" {
		return "Caller-provided file inventory has no unsuppressed secret-like text patterns."
	}
	return "Caller-provided file inventory contains unsuppressed secret-like text patterns or stale suppressions."
}

func findingsToAny(values []findingRecord) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, map[string]any{
			"findingClass": value.FindingClass,
			"line":         value.Line,
			"path":         value.Path,
		})
	}
	return out
}

func suppressedFindingsToAny(values []suppressedFindingRecord) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, map[string]any{
			"findingClass":  value.FindingClass,
			"line":          value.Line,
			"path":          value.Path,
			"reason":        value.Reason,
			"suppressionId": value.SuppressionID,
		})
	}
	return out
}

func suppressionsToAny(values []suppressionRecord) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, map[string]any{
			"findingClass":  value.FindingClass,
			"line":          value.Line,
			"path":          value.Path,
			"reason":        value.Reason,
			"suppressionId": value.SuppressionID,
		})
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
