package requirementsourceadmission

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

const (
	reportKind             = "proofkit.requirement-source-admission"
	outputSchemaVersion    = 2
	boundaryRuleID         = reportKind + ".boundary"
	lifecycleRuleID        = reportKind + ".lifecycle"
	shapeRuleID            = reportKind + ".source-shape"
	boundaryMessage        = "proofkit admits caller-provided requirement source records without owning requirement meaning"
	shapeMessage           = "requirement source package paths derive from the admitted overview.md and requirements.v2.json model"
	lifecyclePassedMessage = "requirement source lifecycle and proof-route admission passed"
	lifecycleFailedMessage = "requirement source lifecycle or proof-route admission failed"
)

var claimLevels = []string{"advisory", "blocking", "deferred"}
var claimLevelSet = toSet(claimLevels)

var lifecycleStates = func() []string {
	variants := requirementsourcemodel.LifecycleStates()
	values := make([]string, len(variants))
	for index, variant := range variants {
		values[index] = string(variant)
	}
	return values
}()
var lifecycleStateSet = toSet(lifecycleStates)

var placeholderPattern = regexp.MustCompile(`(?i)\b(?:fixme|todo|tbd)\b`)

var boundaryNonClaims = []string{
	"Requirement source admission does not decide merge, release, rollout, or freshness.",
	"Requirement source admission does not execute or inspect native witnesses.",
	"Requirement source admission does not own requirement meaning.",
	"Requirement source admission does not prove proof-binding adequacy.",
	"Requirement source admission does not scan overview Markdown for uncited durable claims.",
}

type Requirement struct {
	ClaimLevel           string
	Deferral             *Deferral
	Invariant            string
	Lifecycle            Lifecycle
	NonClaimRefs         []string
	ExternalNonClaimRefs []string
	SharedPremises       []string
	NonClaims            []string
	OwnerID              string
	ProofBindingRefs     []string
	RequirementID        string
	RiskClass            string
	sourceReviewDigest   string
	UpdatePolicy         UpdatePolicy
}

type Lifecycle struct {
	EvidenceRefs              []string
	ReplacementRequirementIDs []string
	State                     string
}

type Deferral struct {
	EvidenceRefs    []string
	ExpiryRef       string
	MergePolicy     string
	OwnerID         string
	ReviewCondition string
	RiskAcceptedBy  string
}

type UpdatePolicy struct {
	RequiresImpactDeclaration  bool
	RequiresProofBindingReview bool
	ReviewOwnerID              string
}

type Source struct {
	model         requirementsourcemodel.Model
	reviewDigests map[string]string
	admitted      bool
}

type Result struct {
	ExitCode int
	Failures []string
	Report   report.Record
	Source   Source
	Summary  requirementsourcemodel.AssessmentSummary
}

func Build(raw any) (report.Record, int, error) {
	result, err := Evaluate(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	return result.Report, result.ExitCode, nil
}

func Evaluate(raw any) (Result, error) {
	assessment, err := requirementsourcecodec.AssessValue(raw)
	if err != nil {
		return Result{}, err
	}
	summary, ok := assessment.Summary()
	if !ok {
		return Result{}, fmt.Errorf("requirement source assessment has no admitted summary")
	}
	failures := []string{}
	for _, violation := range assessment.Violations() {
		failures = append(failures, policyFailure(violation))
	}
	sort.Strings(failures)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append(append([]string{}, boundaryNonClaims...), summary.NonClaims...)
	sort.Strings(nonClaims)
	record := report.Record{
		SchemaVersion: outputSchemaVersion,
		ReportKind:    reportKind,
		ReportID:      summary.SourceID,
		State:         state,
		Summary: map[string]any{
			"activeRequirementCount":   summary.ActiveRequirementCount,
			"blockingRequirementCount": summary.BlockingRequirementCount,
			"deferredRequirementCount": summary.DeferredRequirementCount,
			"failureCount":             len(failures),
			"requirementCount":         summary.RequirementCount,
			"sourcePathCount":          3,
		},
		Diagnostics: []report.Diagnostic{
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
			{Key: "sourcePaths", Value: admit.StringSliceToAny(sortedStrings([]string{OverviewPath(summary.SpecPackagePath), RequirementsPath(summary.SpecPackagePath), summary.SpecPackagePath}))},
		},
		RuleResults: ruleResults(failures),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	if err := sourceOutputShape.CheckGenerated(record.JSONValue(), "requirement source output"); err != nil {
		return Result{}, err
	}
	exitCode := 0
	if state == "failed" {
		exitCode = 1
	}
	var source Source
	if model, ok := assessment.Model(); ok {
		reviewDigests, err := reviewDependencyDigests(model)
		if err != nil {
			return Result{}, err
		}
		source = Source{model: model, reviewDigests: reviewDigests, admitted: true}
	}
	return Result{ExitCode: exitCode, Failures: failures, Report: record, Source: source, Summary: summary}, nil
}

func ruleResults(failures []string) []report.RuleResult {
	return []report.RuleResult{
		{
			RuleID:      boundaryRuleID,
			Status:      "passed",
			Message:     boundaryMessage,
			Diagnostics: []report.Diagnostic{},
		},
		{
			RuleID:      lifecycleRuleID,
			Status:      statusFailedIf(len(failures) > 0),
			Message:     lifecycleMessage(len(failures)),
			Diagnostics: failureDiagnostics(failures),
		},
		{
			RuleID:      shapeRuleID,
			Status:      "passed",
			Message:     shapeMessage,
			Diagnostics: []report.Diagnostic{},
		},
	}
}

func statusFailedIf(value bool) string {
	if value {
		return "failed"
	}
	return "passed"
}

func lifecycleMessage(failureCount int) string {
	if failureCount == 0 {
		return lifecyclePassedMessage
	}
	return lifecycleFailedMessage
}

func failureDiagnostics(failures []string) []report.Diagnostic {
	diagnostics := make([]report.Diagnostic, 0, len(failures))
	for index, failure := range failures {
		diagnostics = append(diagnostics, report.Diagnostic{
			Key:   fmt.Sprintf("failure.%03d", index+1),
			Value: failure,
		})
	}
	return diagnostics
}

func requirementID(raw any, context string) (string, error) {
	value, err := admit.RuleID(raw, context)
	if err != nil {
		return "", err
	}
	if len(value) < 4 || value[:4] != "REQ-" {
		return "", fmt.Errorf("%s must start with REQ-", context)
	}
	return value, nil
}

func invariantText(raw any, context string) (string, error) {
	value, err := text(raw, context)
	if err != nil {
		return "", err
	}
	if placeholderPattern.MatchString(value) {
		return "", fmt.Errorf("%s must not contain placeholder language", context)
	}
	return value, nil
}

func text(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	return value, nil
}

func enum(raw any, values map[string]struct{}, ordered []string, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered))
	}
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered))
	}
	return value, nil
}

func toSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func join(values []string) string {
	if len(values) == 0 {
		return ""
	}
	result := values[0]
	for _, value := range values[1:] {
		result += ", " + value
	}
	return result
}

func sortedStrings(values []string) []string {
	sort.Strings(values)
	return values
}
