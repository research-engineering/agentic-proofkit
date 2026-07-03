package specoverviewclaims

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.spec-overview-claims"

var claimKinds = []string{"durable_claim", "example_or_rationale", "quoted_or_code", "section_heading"}
var claimKindSet = toSet(claimKinds)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

var boundaryNonClaims = []string{
	"Spec overview claim boundary reports do not approve merge, release, rollout, or production readiness.",
	"Spec overview claim boundary reports do not own requirement meaning.",
	"Spec overview claim boundary reports do not prove extractor completeness.",
	"Spec overview claim boundary reports do not read Markdown files.",
	"Spec overview claim boundary reports do not validate requirement source records.",
}

type claim struct {
	CitedRequirementIDs  []string
	ClaimID              string
	ClaimKind            string
	DetectedMarkers      []string
	DispositionRationale string
	LineDigest           string
	LineNumber           int
	NonClaims            []string
}

type boundary struct {
	BoundaryID       string
	Claims           []claim
	ExtractionRefs   []string
	NonClaims        []string
	OverviewPath     string
	RequirementIDs   []string
	RequirementsPath string
	SourceID         string
	SpecPackagePath  string
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitBoundary(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	pathFailures := boundaryFailures(input)
	sort.Strings(pathFailures)
	requirementIDs := toSet(input.RequirementIDs)
	citationFailures := []string{}
	for _, item := range input.Claims {
		citationFailures = append(citationFailures, claimFailures(item, requirementIDs)...)
	}
	sort.Strings(citationFailures)
	failures := append(append([]string{}, pathFailures...), citationFailures...)
	sort.Strings(failures)
	durableClaimCount := 0
	citedDurableClaimCount := 0
	for _, item := range input.Claims {
		if item.ClaimKind != "durable_claim" {
			continue
		}
		durableClaimCount++
		if len(item.CitedRequirementIDs) > 0 {
			citedDurableClaimCount++
		}
	}
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append(append([]string{}, boundaryNonClaims...), input.NonClaims...)
	sort.Strings(nonClaims)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.BoundaryID,
		State:         state,
		Summary: map[string]any{
			"citedDurableClaimCount":   citedDurableClaimCount,
			"claimCount":               len(input.Claims),
			"durableClaimCount":        durableClaimCount,
			"extractionRefCount":       len(input.ExtractionRefs),
			"failureCount":             len(failures),
			"nonNormativeClaimCount":   len(input.Claims) - durableClaimCount,
			"requirementIdCount":       len(input.RequirementIDs),
			"uncitedDurableClaimCount": durableClaimCount - citedDurableClaimCount,
		},
		Diagnostics: []report.Diagnostic{
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
			{Key: "overview", Value: map[string]any{
				"overviewPath":     input.OverviewPath,
				"requirementsPath": input.RequirementsPath,
				"specPackagePath":  input.SpecPackagePath,
			}},
		},
		RuleResults: ruleResults(pathFailures, citationFailures),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	if state == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}

func admitBoundary(raw any) (boundary, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return boundary{}, fmt.Errorf("spec overview claim boundary input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"boundaryId", "claims", "extractionRefs", "nonClaims", "overviewPath", "requirementIds", "requirementsPath", "schemaVersion", "sourceId", "specPackagePath"}, "spec overview claim boundary input"); err != nil {
		return boundary{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return boundary{}, fmt.Errorf("spec overview claim boundary schemaVersion must be 1")
	}
	claims, err := claimArray(record["claims"])
	if err != nil {
		return boundary{}, err
	}
	boundaryID, err := admit.RuleID(record["boundaryId"], "spec overview claim boundaryId")
	if err != nil {
		return boundary{}, err
	}
	sourceID, err := admit.RuleID(record["sourceId"], "spec overview claim sourceId")
	if err != nil {
		return boundary{}, err
	}
	specPackagePath, err := pathField(record["specPackagePath"], "spec overview claim specPackagePath")
	if err != nil {
		return boundary{}, err
	}
	overviewPath, err := pathField(record["overviewPath"], "spec overview claim overviewPath")
	if err != nil {
		return boundary{}, err
	}
	requirementsPath, err := pathField(record["requirementsPath"], "spec overview claim requirementsPath")
	if err != nil {
		return boundary{}, err
	}
	requirementIDs, err := sortedRequirementIDs(record["requirementIds"], "spec overview claim requirementIds", false)
	if err != nil {
		return boundary{}, err
	}
	extractionRefs, err := sortedPaths(record["extractionRefs"], "spec overview claim extractionRefs", false)
	if err != nil {
		return boundary{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "spec overview claim nonClaims", false)
	if err != nil {
		return boundary{}, err
	}
	return boundary{
		BoundaryID:       boundaryID,
		Claims:           claims,
		ExtractionRefs:   extractionRefs,
		NonClaims:        nonClaims,
		OverviewPath:     overviewPath,
		RequirementIDs:   requirementIDs,
		RequirementsPath: requirementsPath,
		SourceID:         sourceID,
		SpecPackagePath:  specPackagePath,
	}, nil
}

func claimArray(raw any) ([]claim, error) {
	records, err := arrayOfRecords(raw, "spec overview claim records", true)
	if err != nil {
		return nil, err
	}
	result := make([]claim, 0, len(records))
	for _, record := range records {
		item, err := admitClaim(record)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].ClaimID < result[right].ClaimID
	})
	ids := make([]string, 0, len(result))
	for _, item := range result {
		ids = append(ids, item.ClaimID)
	}
	if err := preserveSortedUnique(ids, "spec overview claim ids", true); err != nil {
		return nil, err
	}
	return result, nil
}

func admitClaim(record map[string]any) (claim, error) {
	if err := admit.KnownKeys(record, []string{"citedRequirementIds", "claimId", "claimKind", "detectedMarkers", "dispositionRationale", "lineDigest", "lineNumber", "nonClaims"}, "spec overview claim record"); err != nil {
		return claim{}, err
	}
	claimID, err := admit.RuleID(record["claimId"], "spec overview claim claimId")
	if err != nil {
		return claim{}, err
	}
	lineNumber, err := admit.PositiveInteger(record["lineNumber"], fmt.Sprintf("spec overview claim %s lineNumber", claimID))
	if err != nil {
		return claim{}, err
	}
	lineDigest, err := digest(record["lineDigest"], fmt.Sprintf("spec overview claim %s lineDigest", claimID))
	if err != nil {
		return claim{}, err
	}
	claimKind, err := enum(record["claimKind"], claimKindSet, claimKinds, fmt.Sprintf("spec overview claim %s claimKind", claimID))
	if err != nil {
		return claim{}, err
	}
	detectedMarkers, err := sortedText(record["detectedMarkers"], fmt.Sprintf("spec overview claim %s detectedMarkers", claimID), false)
	if err != nil {
		return claim{}, err
	}
	citedRequirementIDs, err := sortedRequirementIDs(record["citedRequirementIds"], fmt.Sprintf("spec overview claim %s citedRequirementIds", claimID), true)
	if err != nil {
		return claim{}, err
	}
	dispositionRationale, err := admit.NonEmptyText(record["dispositionRationale"], fmt.Sprintf("spec overview claim %s dispositionRationale", claimID))
	if err != nil {
		return claim{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], fmt.Sprintf("spec overview claim %s nonClaims", claimID), false)
	if err != nil {
		return claim{}, err
	}
	return claim{
		CitedRequirementIDs:  citedRequirementIDs,
		ClaimID:              claimID,
		ClaimKind:            claimKind,
		DetectedMarkers:      detectedMarkers,
		DispositionRationale: dispositionRationale,
		LineDigest:           lineDigest,
		LineNumber:           lineNumber,
		NonClaims:            nonClaims,
	}, nil
}

func boundaryFailures(input boundary) []string {
	failures := []string{}
	if input.OverviewPath != input.SpecPackagePath+"/overview.md" {
		failures = append(failures, "overviewPath must equal specPackagePath/overview.md")
	}
	if input.RequirementsPath != input.SpecPackagePath+"/requirements.v1.json" {
		failures = append(failures, "requirementsPath must equal specPackagePath/requirements.v1.json")
	}
	return failures
}

func claimFailures(item claim, requirementIDs map[string]struct{}) []string {
	failures := []string{}
	if item.ClaimKind == "durable_claim" && len(item.CitedRequirementIDs) == 0 {
		failures = append(failures, fmt.Sprintf("durable overview claim must cite at least one requirement id: %s", item.ClaimID))
	}
	for _, requirementID := range item.CitedRequirementIDs {
		if _, ok := requirementIDs[requirementID]; !ok {
			failures = append(failures, fmt.Sprintf("overview claim cites unknown requirement id %s: %s", requirementID, item.ClaimID))
		}
	}
	if item.ClaimKind != "durable_claim" && len(item.CitedRequirementIDs) > 0 {
		failures = append(failures, fmt.Sprintf("non-durable overview claim must not carry requirement citations: %s", item.ClaimID))
	}
	return failures
}

func ruleResults(pathFailures []string, citationFailures []string) []report.RuleResult {
	return []report.RuleResult{
		{
			RuleID:      "proofkit.spec-overview-claims.boundary",
			Status:      statusFailedIf(len(pathFailures) > 0),
			Message:     "spec overview claim boundaries are validated from caller-provided extraction facts",
			Diagnostics: failureDiagnostics(pathFailures),
		},
		{
			RuleID:      "proofkit.spec-overview-claims.citations",
			Status:      statusFailedIf(len(citationFailures) > 0),
			Message:     "durable overview claims must cite known requirement ids and non-durable claims must remain non-normative",
			Diagnostics: failureDiagnostics(citationFailures),
		},
	}
}

func failureDiagnostics(failures []string) []report.Diagnostic {
	diagnostics := make([]report.Diagnostic, 0, len(failures))
	for index, failure := range failures {
		diagnostics = append(diagnostics, report.Diagnostic{Key: fmt.Sprintf("failure.%03d", index+1), Value: failure})
	}
	return diagnostics
}

func arrayOfRecords(raw any, context string, allowEmpty bool) ([]map[string]any, error) {
	values, ok := raw.([]any)
	if !ok || (!allowEmpty && len(values) == 0) {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]map[string]any, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", context, index)
		}
		result = append(result, record)
	}
	return result, nil
}

func sortedPaths(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a sorted unique path array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		path, err := pathField(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, path)
	}
	return preserveInputSortedUnique(result, context, allowEmpty)
}

func sortedRequirementIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a sorted unique requirement-id array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		requirementID, err := admitRequirementID(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, requirementID)
	}
	return preserveInputSortedUnique(result, context, allowEmpty)
}

func admitRequirementID(raw any, context string) (string, error) {
	value, err := admit.RuleID(raw, context)
	if err != nil {
		return "", err
	}
	if len(value) < 4 || value[:4] != "REQ-" {
		return "", fmt.Errorf("%s must start with REQ-", context)
	}
	return value, nil
}

func sortedText(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a sorted unique string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := admit.NonEmptyText(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	return preserveInputSortedUnique(result, context, allowEmpty)
}

func preserveInputSortedUnique(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	if err := preserveSortedUnique(values, context, allowEmpty); err != nil {
		return nil, err
	}
	return values, nil
}

func preserveSortedUnique(values []string, context string, allowEmpty bool) error {
	if !allowEmpty && len(values) == 0 {
		return fmt.Errorf("%s must be non-empty", context)
	}
	for index := range values {
		if index > 0 && (values[index-1] == values[index] || values[index-1] > values[index]) {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return nil
}

func pathField(raw any, context string) (string, error) {
	text, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(text, context)
}

func digest(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || !digestPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be sha256:<64 lowercase hex>", context)
	}
	return value, nil
}

func enum(raw any, values map[string]struct{}, ordered []string, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered, ", "))
	}
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered, ", "))
	}
	return value, nil
}

func statusFailedIf(value bool) string {
	if value {
		return "failed"
	}
	return "passed"
}

func toSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func join(values []string, separator string) string {
	if len(values) == 0 {
		return ""
	}
	result := values[0]
	for _, value := range values[1:] {
		result += separator + value
	}
	return result
}
