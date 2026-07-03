package requirementsourceadmission

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.requirement-source-admission"

var claimLevels = []string{"advisory", "blocking", "deferred"}
var claimLevelSet = toSet(claimLevels)

var lifecycleStates = []string{"active", "deprecated", "removed", "superseded"}
var lifecycleStateSet = toSet(lifecycleStates)

var riskClasses = []string{"critical", "high", "low", "medium"}
var riskClassSet = toSet(riskClasses)

var placeholderPattern = regexp.MustCompile(`(?i)\b(?:fixme|todo|tbd)\b`)

var boundaryNonClaims = []string{
	"Requirement source admission does not decide merge, release, rollout, or freshness.",
	"Requirement source admission does not execute or inspect native witnesses.",
	"Requirement source admission does not own requirement meaning.",
	"Requirement source admission does not prove proof-binding adequacy.",
	"Requirement source admission does not scan overview Markdown for uncited durable claims.",
}

type Requirement struct {
	ClaimLevel       string
	Deferral         *Deferral
	Invariant        string
	Lifecycle        Lifecycle
	NonClaimRefs     []string
	NonClaims        []string
	OwnerID          string
	ProofBindingRefs []string
	RequirementID    string
	RiskClass        string
	UpdatePolicy     UpdatePolicy
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
	NonClaims        []string
	OverviewPath     string
	Requirements     []Requirement
	RequirementsPath string
	SourceID         string
	SpecPackagePath  string
}

type Result struct {
	ExitCode int
	Failures []string
	Report   report.Record
	Source   Source
}

func Build(raw any) (report.Record, int, error) {
	result, err := Evaluate(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	return result.Report, result.ExitCode, nil
}

func Evaluate(raw any) (Result, error) {
	source, err := admitSource(raw)
	if err != nil {
		return Result{}, err
	}
	failures := sourceFailures(source)
	sort.Strings(failures)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append(append([]string{}, boundaryNonClaims...), source.NonClaims...)
	sort.Strings(nonClaims)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      source.SourceID,
		State:         state,
		Summary: map[string]any{
			"activeRequirementCount":   countLifecycle(source.Requirements, "active"),
			"blockingRequirementCount": countClaimLevel(source.Requirements, "blocking"),
			"deferredRequirementCount": countClaimLevel(source.Requirements, "deferred"),
			"failureCount":             len(failures),
			"requirementCount":         len(source.Requirements),
			"sourcePathCount":          3,
		},
		Diagnostics: []report.Diagnostic{
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
			{Key: "sourcePaths", Value: admit.StringSliceToAny(sortedStrings([]string{source.OverviewPath, source.RequirementsPath, source.SpecPackagePath}))},
		},
		RuleResults: ruleResults(failures),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	exitCode := 0
	if state == "failed" {
		exitCode = 1
	}
	return Result{ExitCode: exitCode, Failures: failures, Report: record, Source: source}, nil
}

func admitSource(raw any) (Source, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Source{}, fmt.Errorf("requirement source admission input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"nonClaims", "overviewPath", "requirements", "requirementsPath", "schemaVersion", "sourceId", "specPackagePath"}, "requirement source admission input"); err != nil {
		return Source{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return Source{}, fmt.Errorf("requirement source admission schemaVersion must be 1")
	}
	specPackagePath, err := pathField(record["specPackagePath"], "requirement source specPackagePath")
	if err != nil {
		return Source{}, err
	}
	overviewPath, err := pathField(record["overviewPath"], "requirement source overviewPath")
	if err != nil {
		return Source{}, err
	}
	requirementsPath, err := pathField(record["requirementsPath"], "requirement source requirementsPath")
	if err != nil {
		return Source{}, err
	}
	requirements, err := requirements(record["requirements"])
	if err != nil {
		return Source{}, err
	}
	requirementIDs := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		requirementIDs = append(requirementIDs, requirement.RequirementID)
	}
	if _, err := preserveSortedUnique(requirementIDs, "requirement source requirementIds", true); err != nil {
		return Source{}, err
	}
	sourceID, err := admit.RuleID(record["sourceId"], "requirement source sourceId")
	if err != nil {
		return Source{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "requirement source nonClaims", false)
	if err != nil {
		return Source{}, err
	}
	return Source{
		NonClaims:        nonClaims,
		OverviewPath:     overviewPath,
		Requirements:     requirements,
		RequirementsPath: requirementsPath,
		SourceID:         sourceID,
		SpecPackagePath:  specPackagePath,
	}, nil
}

func requirements(raw any) ([]Requirement, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("requirement source requirements must be an array")
	}
	result := make([]Requirement, 0, len(values))
	for _, value := range values {
		requirement, err := admitRequirement(value)
		if err != nil {
			return nil, err
		}
		result = append(result, requirement)
	}
	return result, nil
}

func admitRequirement(raw any) (Requirement, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Requirement{}, fmt.Errorf("requirement source record must be an object")
	}
	if err := admit.KnownKeys(record, []string{"claimLevel", "deferral", "invariant", "lifecycle", "nonClaimRefs", "nonClaims", "ownerId", "proofBindingRefs", "requirementId", "riskClass", "updatePolicy"}, "requirement source record"); err != nil {
		return Requirement{}, err
	}
	requirementID, err := requirementID(record["requirementId"], "requirement source requirementId")
	if err != nil {
		return Requirement{}, err
	}
	ownerID, err := admit.RuleID(record["ownerId"], fmt.Sprintf("requirement source %s ownerId", requirementID))
	if err != nil {
		return Requirement{}, err
	}
	invariant, err := invariantText(record["invariant"], fmt.Sprintf("requirement source %s invariant", requirementID))
	if err != nil {
		return Requirement{}, err
	}
	claimLevel, err := enum(record["claimLevel"], claimLevelSet, claimLevels, fmt.Sprintf("requirement source %s claimLevel", requirementID))
	if err != nil {
		return Requirement{}, err
	}
	riskClass, err := enum(record["riskClass"], riskClassSet, riskClasses, fmt.Sprintf("requirement source %s riskClass", requirementID))
	if err != nil {
		return Requirement{}, err
	}
	proofBindingRefs, err := sortedPaths(record["proofBindingRefs"], fmt.Sprintf("requirement source %s proofBindingRefs", requirementID), true)
	if err != nil {
		return Requirement{}, err
	}
	nonClaimRefs, err := sortedRuleIDs(record["nonClaimRefs"], fmt.Sprintf("requirement source %s nonClaimRefs", requirementID), true)
	if err != nil {
		return Requirement{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], fmt.Sprintf("requirement source %s nonClaims", requirementID), true)
	if err != nil {
		return Requirement{}, err
	}
	lifecycle, err := admitLifecycle(record["lifecycle"], requirementID)
	if err != nil {
		return Requirement{}, err
	}
	var deferral *Deferral
	if record["deferral"] != nil {
		value, err := admitDeferral(record["deferral"], requirementID)
		if err != nil {
			return Requirement{}, err
		}
		deferral = &value
	}
	updatePolicy, err := admitUpdatePolicy(record["updatePolicy"], requirementID)
	if err != nil {
		return Requirement{}, err
	}
	return Requirement{
		ClaimLevel:       claimLevel,
		Deferral:         deferral,
		Invariant:        invariant,
		Lifecycle:        lifecycle,
		NonClaimRefs:     nonClaimRefs,
		NonClaims:        nonClaims,
		OwnerID:          ownerID,
		ProofBindingRefs: proofBindingRefs,
		RequirementID:    requirementID,
		RiskClass:        riskClass,
		UpdatePolicy:     updatePolicy,
	}, nil
}

func admitLifecycle(raw any, requirementID string) (Lifecycle, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Lifecycle{}, fmt.Errorf("requirement source %s lifecycle must be an object", requirementID)
	}
	if err := admit.KnownKeys(record, []string{"evidenceRefs", "replacementRequirementIds", "state"}, fmt.Sprintf("requirement source %s lifecycle", requirementID)); err != nil {
		return Lifecycle{}, err
	}
	state, err := enum(record["state"], lifecycleStateSet, lifecycleStates, fmt.Sprintf("requirement source %s lifecycle.state", requirementID))
	if err != nil {
		return Lifecycle{}, err
	}
	replacementRequirementIDs, err := sortedRequirementIDs(record["replacementRequirementIds"], fmt.Sprintf("requirement source %s lifecycle.replacementRequirementIds", requirementID), true)
	if err != nil {
		return Lifecycle{}, err
	}
	evidenceRefs, err := sortedPaths(record["evidenceRefs"], fmt.Sprintf("requirement source %s lifecycle.evidenceRefs", requirementID), true)
	if err != nil {
		return Lifecycle{}, err
	}
	return Lifecycle{EvidenceRefs: evidenceRefs, ReplacementRequirementIDs: replacementRequirementIDs, State: state}, nil
}

func admitDeferral(raw any, requirementID string) (Deferral, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Deferral{}, fmt.Errorf("requirement source %s deferral must be an object or null", requirementID)
	}
	if err := admit.KnownKeys(record, []string{"evidenceRefs", "expiryRef", "mergePolicy", "ownerId", "reviewCondition", "riskAcceptedBy"}, fmt.Sprintf("requirement source %s deferral", requirementID)); err != nil {
		return Deferral{}, err
	}
	ownerID, err := admit.RuleID(record["ownerId"], fmt.Sprintf("requirement source %s deferral.ownerId", requirementID))
	if err != nil {
		return Deferral{}, err
	}
	riskAcceptedBy, err := admit.RuleID(record["riskAcceptedBy"], fmt.Sprintf("requirement source %s deferral.riskAcceptedBy", requirementID))
	if err != nil {
		return Deferral{}, err
	}
	reviewCondition, err := text(record["reviewCondition"], fmt.Sprintf("requirement source %s deferral.reviewCondition", requirementID))
	if err != nil {
		return Deferral{}, err
	}
	expiryRef, err := admit.RuleID(record["expiryRef"], fmt.Sprintf("requirement source %s deferral.expiryRef", requirementID))
	if err != nil {
		return Deferral{}, err
	}
	mergePolicy, err := admit.RuleID(record["mergePolicy"], fmt.Sprintf("requirement source %s deferral.mergePolicy", requirementID))
	if err != nil {
		return Deferral{}, err
	}
	evidenceRefs, err := sortedPaths(record["evidenceRefs"], fmt.Sprintf("requirement source %s deferral.evidenceRefs", requirementID), false)
	if err != nil {
		return Deferral{}, err
	}
	return Deferral{
		EvidenceRefs:    evidenceRefs,
		ExpiryRef:       expiryRef,
		MergePolicy:     mergePolicy,
		OwnerID:         ownerID,
		ReviewCondition: reviewCondition,
		RiskAcceptedBy:  riskAcceptedBy,
	}, nil
}

func admitUpdatePolicy(raw any, requirementID string) (UpdatePolicy, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return UpdatePolicy{}, fmt.Errorf("requirement source %s updatePolicy must be an object", requirementID)
	}
	if err := admit.KnownKeys(record, []string{"requiresImpactDeclaration", "requiresProofBindingReview", "reviewOwnerId"}, fmt.Sprintf("requirement source %s updatePolicy", requirementID)); err != nil {
		return UpdatePolicy{}, err
	}
	reviewOwnerID, err := admit.RuleID(record["reviewOwnerId"], fmt.Sprintf("requirement source %s updatePolicy.reviewOwnerId", requirementID))
	if err != nil {
		return UpdatePolicy{}, err
	}
	requiresImpactDeclaration, err := admit.Bool(record["requiresImpactDeclaration"], fmt.Sprintf("requirement source %s updatePolicy.requiresImpactDeclaration", requirementID))
	if err != nil {
		return UpdatePolicy{}, err
	}
	requiresProofBindingReview, err := admit.Bool(record["requiresProofBindingReview"], fmt.Sprintf("requirement source %s updatePolicy.requiresProofBindingReview", requirementID))
	if err != nil {
		return UpdatePolicy{}, err
	}
	return UpdatePolicy{
		RequiresImpactDeclaration:  requiresImpactDeclaration,
		RequiresProofBindingReview: requiresProofBindingReview,
		ReviewOwnerID:              reviewOwnerID,
	}, nil
}

func sourceFailures(source Source) []string {
	failures := []string{}
	if source.OverviewPath != source.SpecPackagePath+"/overview.md" {
		failures = append(failures, "overviewPath must equal specPackagePath/overview.md")
	}
	if source.RequirementsPath != source.SpecPackagePath+"/requirements.v1.json" {
		failures = append(failures, "requirementsPath must equal specPackagePath/requirements.v1.json")
	}
	requirementsByID := map[string]Requirement{}
	for _, requirement := range source.Requirements {
		requirementsByID[requirement.RequirementID] = requirement
	}
	for _, requirement := range source.Requirements {
		failures = append(failures, requirementFailures(requirement, requirementsByID)...)
	}
	return failures
}

func requirementFailures(requirement Requirement, requirementsByID map[string]Requirement) []string {
	failures := []string{}
	if requirement.ClaimLevel == "blocking" && requirement.Lifecycle.State == "active" {
		if len(requirement.ProofBindingRefs) == 0 {
			failures = append(failures, fmt.Sprintf("active blocking requirement must route to proof bindings: %s", requirement.RequirementID))
		}
		if !requirement.UpdatePolicy.RequiresImpactDeclaration {
			failures = append(failures, fmt.Sprintf("active blocking requirement must require impact declaration on change: %s", requirement.RequirementID))
		}
		if !requirement.UpdatePolicy.RequiresProofBindingReview {
			failures = append(failures, fmt.Sprintf("active blocking requirement must require proof-binding review on change: %s", requirement.RequirementID))
		}
	}
	if requirement.ClaimLevel == "deferred" && requirement.Deferral == nil {
		failures = append(failures, fmt.Sprintf("deferred requirement must declare deferral policy: %s", requirement.RequirementID))
	}
	if requirement.ClaimLevel != "deferred" && requirement.Deferral != nil {
		failures = append(failures, fmt.Sprintf("non-deferred requirement must not declare deferral policy: %s", requirement.RequirementID))
	}
	if requirement.Lifecycle.State != "active" && len(requirement.Lifecycle.EvidenceRefs) == 0 {
		failures = append(failures, fmt.Sprintf("non-active requirement must declare lifecycle evidenceRefs: %s", requirement.RequirementID))
	}
	if requirement.Lifecycle.State != "superseded" && len(requirement.Lifecycle.ReplacementRequirementIDs) > 0 {
		failures = append(failures, fmt.Sprintf("only superseded requirements may declare replacementRequirementIds: %s", requirement.RequirementID))
	}
	if requirement.Lifecycle.State == "superseded" && len(requirement.Lifecycle.ReplacementRequirementIDs) == 0 {
		failures = append(failures, fmt.Sprintf("superseded requirement must declare replacementRequirementIds: %s", requirement.RequirementID))
	}
	for _, replacementID := range requirement.Lifecycle.ReplacementRequirementIDs {
		if replacementID == requirement.RequirementID {
			failures = append(failures, fmt.Sprintf("requirement must not replace itself: %s", requirement.RequirementID))
		}
		replacement, ok := requirementsByID[replacementID]
		if !ok {
			failures = append(failures, fmt.Sprintf("replacement requirement must be present in the same source: %s -> %s", requirement.RequirementID, replacementID))
			continue
		}
		if replacement.Lifecycle.State != "active" {
			failures = append(failures, fmt.Sprintf("replacement requirement must be active in the same source: %s -> %s", requirement.RequirementID, replacementID))
		}
	}
	if requirement.ClaimLevel == "blocking" && requirement.Lifecycle.State != "active" {
		failures = append(failures, fmt.Sprintf("non-active requirement must not remain blocking: %s", requirement.RequirementID))
	}
	return failures
}

func ruleResults(failures []string) []report.RuleResult {
	pathFailures := []string{}
	lifecycleFailures := []string{}
	for _, failure := range failures {
		if stringsHasPrefix(failure, "overviewPath ") || stringsHasPrefix(failure, "requirementsPath ") {
			pathFailures = append(pathFailures, failure)
		} else {
			lifecycleFailures = append(lifecycleFailures, failure)
		}
	}
	return []report.RuleResult{
		{
			RuleID:      "proofkit.requirement-source-admission.boundary",
			Status:      "passed",
			Message:     "proofkit admits caller-provided requirement source records without owning requirement meaning",
			Diagnostics: []report.Diagnostic{},
		},
		{
			RuleID:      "proofkit.requirement-source-admission.lifecycle",
			Status:      statusFailedIf(len(lifecycleFailures) > 0),
			Message:     lifecycleMessage(len(lifecycleFailures)),
			Diagnostics: failureDiagnostics(lifecycleFailures),
		},
		{
			RuleID:      "proofkit.requirement-source-admission.source-shape",
			Status:      statusFailedIf(len(pathFailures) > 0),
			Message:     "requirement source package paths must follow the overview.md and requirements.v1.json model",
			Diagnostics: failureDiagnostics(pathFailures),
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
		return "requirement source lifecycle and proof-route admission passed"
	}
	return "requirement source lifecycle or proof-route admission failed"
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

func sortedRequirementIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, requirementID)
}

func sortedRuleIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, admit.RuleID)
}

func sortedPaths(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, func(value any, itemContext string) (string, error) {
		return pathField(value, itemContext)
	})
}

func sortedText(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, text)
}

func sortedMapped(raw any, context string, allowEmpty bool, mapper func(any, string) (string, error)) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a sorted unique string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		item, err := mapper(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return preserveSortedUnique(result, context, allowEmpty)
}

func preserveSortedUnique(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	for index := range values {
		if values[index] != sorted[index] || (index > 0 && values[index-1] == values[index]) {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return values, nil
}

func pathField(raw any, context string) (string, error) {
	value, err := text(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(value, context)
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

func countLifecycle(requirements []Requirement, state string) int {
	count := 0
	for _, requirement := range requirements {
		if requirement.Lifecycle.State == state {
			count++
		}
	}
	return count
}

func countClaimLevel(requirements []Requirement, claimLevel string) int {
	count := 0
	for _, requirement := range requirements {
		if requirement.ClaimLevel == claimLevel {
			count++
		}
	}
	return count
}

func stringsHasPrefix(value string, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}
