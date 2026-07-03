package branchauthority

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.branch-authority"

var unsafeBranchPattern = regexp.MustCompile(`[ \t\r\n~^:?*\[\]\\]`)

var refKinds = map[string]struct{}{
	"branch_protection":     {},
	"ci_push":               {},
	"consumer_fixture":      {},
	"manual_workflow_guard": {},
	"package_source":        {},
	"publish_guard":         {},
	"release_source":        {},
	"repository_default":    {},
	"review_base":           {},
}

var branchAuthorityNonClaims = []any{
	"Branch authority reports do not discover repository settings.",
	"Branch authority reports do not parse workflow files.",
	"Branch authority reports do not mutate branch settings.",
	"Branch authority reports do not prove CI execution, package publication, release approval, or rollout readiness.",
	"Branch authority reports do not own consumer branch policy.",
}

type refInput struct {
	EvidenceRef    string
	ExpectedBranch string
	NonClaims      []string
	ObservedBranch string
	RefID          string
	RefKind        string
	Required       bool
}

type admittedInput struct {
	BranchRefs          []refInput
	NonClaims           []any
	PreexistingFailures []string
	ReportID            string
}

func Build(raw any) (report.Record, int) {
	input, err := admitInput(raw)
	if err != nil {
		return invalidInputReport(err.Error()), 1
	}
	branchRefs := make([]any, 0, len(input.BranchRefs))
	requiredDrift := []string{}
	advisoryDrift := []string{}
	for _, ref := range input.BranchRefs {
		alignment := "aligned"
		if ref.ObservedBranch != ref.ExpectedBranch {
			alignment = "drifted"
			if ref.Required {
				requiredDrift = append(requiredDrift, ref.RefID)
			} else {
				advisoryDrift = append(advisoryDrift, ref.RefID)
			}
		}
		branchRefs = append(branchRefs, map[string]any{
			"alignment":      alignment,
			"evidenceRef":    ref.EvidenceRef,
			"expectedBranch": ref.ExpectedBranch,
			"nonClaims":      admit.StringSliceToAny(ref.NonClaims),
			"observedBranch": ref.ObservedBranch,
			"refId":          ref.RefID,
			"refKind":        ref.RefKind,
			"required":       ref.Required,
		})
	}
	failures := append([]string{}, input.PreexistingFailures...)
	for _, refID := range requiredDrift {
		failures = append(failures, fmt.Sprintf("required branch ref %s drifted", refID))
	}
	sort.Strings(failures)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.ReportID,
		State:         state,
		Summary: map[string]any{
			"advisoryDriftCount": len(advisoryDrift),
			"branchRefCount":     len(branchRefs),
			"requiredDriftCount": len(requiredDrift),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "advisoryDriftRefIds", Value: admit.StringSliceToAny(advisoryDrift)},
			{Key: "branchRefs", Value: branchRefs},
			{Key: "requiredDriftRefIds", Value: admit.StringSliceToAny(requiredDrift)},
		},
		RuleResults: []report.RuleResult{
			rule("branch_authority.advisory_refs_visible", statusWarningIf(len(advisoryDrift) > 0), messageAdvisory(len(advisoryDrift))),
			rule("branch_authority.preexisting_failures", statusFailedIf(len(input.PreexistingFailures) > 0), messagePreexisting(len(input.PreexistingFailures))),
			rule("branch_authority.required_refs_aligned", statusFailedIf(len(requiredDrift) > 0), messageRequired(len(requiredDrift))),
		},
		NonClaims: input.NonClaims,
	}
	if state == "passed" {
		return record, 0
	}
	return record, 1
}

func invalidInputReport(failure string) report.Record {
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      "invalid-input",
		State:         "failed",
		Summary: map[string]any{
			"advisoryDriftCount": 0,
			"branchRefCount":     0,
			"requiredDriftCount": 0,
		},
		Diagnostics: []report.Diagnostic{},
		RuleResults: []report.RuleResult{
			rule("branch_authority.input", "failed", failure),
		},
		NonClaims: branchAuthorityNonClaims,
	}
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("branch authority input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"branchRefs", "nonClaims", "preexistingFailures", "reportId", "schemaVersion"}, "branch authority input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("branch authority schemaVersion must be 1")
	}
	reportID, err := admit.RuleID(record["reportId"], "branch authority reportId")
	if err != nil {
		return admittedInput{}, err
	}
	refs, err := branchRefs(record["branchRefs"])
	if err != nil {
		return admittedInput{}, err
	}
	preexistingRaw, err := admit.TextArray(record["preexistingFailures"], "branch authority preexistingFailures", true)
	if err != nil {
		return admittedInput{}, err
	}
	preexisting, err := admit.SortedText(preexistingRaw, "branch authority preexistingFailures", true)
	if err != nil {
		return admittedInput{}, err
	}
	inputNonClaims, err := admit.TextArray(record["nonClaims"], "branch authority nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	allNonClaims := append(admit.AnySliceToString(branchAuthorityNonClaims), inputNonClaims...)
	nonClaims, err := admit.SortedText(allNonClaims, "branch authority nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		BranchRefs:          refs,
		NonClaims:           admit.StringSliceToAny(nonClaims),
		PreexistingFailures: preexisting,
		ReportID:            reportID,
	}, nil
}

func branchRefs(raw any) ([]refInput, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("branch authority branchRefs must be a non-empty array")
	}
	refs := make([]refInput, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("branch authority ref %d must be an object", index+1)
		}
		if err := admit.KnownKeys(record, []string{"evidenceRef", "expectedBranch", "nonClaims", "observedBranch", "refId", "refKind", "required"}, fmt.Sprintf("branch authority ref %d", index+1)); err != nil {
			return nil, err
		}
		refID, err := admit.RuleID(record["refId"], fmt.Sprintf("branch authority ref %d refId", index+1))
		if err != nil {
			return nil, err
		}
		refKind, err := admit.Enum(record["refKind"], refKinds, fmt.Sprintf("branch authority ref %s refKind", refID))
		if err != nil {
			return nil, err
		}
		observed, err := branchName(record["observedBranch"], fmt.Sprintf("branch authority ref %s observedBranch", refID))
		if err != nil {
			return nil, err
		}
		expected, err := branchName(record["expectedBranch"], fmt.Sprintf("branch authority ref %s expectedBranch", refID))
		if err != nil {
			return nil, err
		}
		required, err := admit.Bool(record["required"], fmt.Sprintf("branch authority ref %s required", refID))
		if err != nil {
			return nil, err
		}
		evidenceRef, err := admit.NonEmptyText(record["evidenceRef"], fmt.Sprintf("branch authority ref %s evidenceRef", refID))
		if err != nil {
			return nil, err
		}
		nonClaimsRaw, err := admit.TextArray(record["nonClaims"], fmt.Sprintf("branch authority ref %s nonClaims", refID), false)
		if err != nil {
			return nil, err
		}
		nonClaims, err := admit.SortedText(nonClaimsRaw, fmt.Sprintf("branch authority ref %s nonClaims", refID), false)
		if err != nil {
			return nil, err
		}
		refs = append(refs, refInput{
			EvidenceRef:    evidenceRef,
			ExpectedBranch: expected,
			NonClaims:      nonClaims,
			ObservedBranch: observed,
			RefID:          refID,
			RefKind:        refKind,
			Required:       required,
		})
	}
	sort.Slice(refs, func(left, right int) bool {
		return refs[left].RefID < refs[right].RefID
	})
	for index := 1; index < len(refs); index++ {
		if refs[index-1].RefID == refs[index].RefID {
			return nil, fmt.Errorf("branch authority ref ids must be sorted and unique")
		}
	}
	return refs, nil
}

func branchName(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if strings.Contains(value, "..") ||
		strings.Contains(value, "//") ||
		strings.Contains(value, `\`) ||
		strings.HasPrefix(value, "/") ||
		strings.HasSuffix(value, "/") ||
		strings.HasSuffix(value, ".lock") ||
		unsafeBranchPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be a safe branch ref", context)
	}
	return value, nil
}

func rule(ruleID string, status string, message string) report.RuleResult {
	return report.RuleResult{RuleID: ruleID, Status: status, Message: message}
}

func statusFailedIf(failed bool) string {
	if failed {
		return "failed"
	}
	return "passed"
}

func statusWarningIf(warning bool) string {
	if warning {
		return "warning"
	}
	return "passed"
}

func messageRequired(count int) string {
	if count == 0 {
		return "all required branch refs match caller expected branches"
	}
	return "required branch refs drifted from caller expected branches"
}

func messageAdvisory(count int) string {
	if count == 0 {
		return "no advisory branch drift"
	}
	return "advisory branch drift is visible but does not fail this report"
}

func messagePreexisting(count int) string {
	if count == 0 {
		return "no caller preexisting branch authority failures"
	}
	return "caller supplied preexisting branch authority failures"
}
