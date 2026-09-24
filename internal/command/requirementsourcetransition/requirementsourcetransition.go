package requirementsourcetransition

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

const (
	reportKind            = "proofkit.requirement-source-transition"
	inputSchemaVersion    = 2
	outputSchemaVersion   = 2
	boundaryRuleID        = reportKind + ".boundary"
	sourceRuleID          = reportKind + ".source-admission"
	latticeRuleID         = reportKind + ".transition-lattice"
	boundaryMessage       = "proofkit compares caller-provided snapshots for one requirement source package"
	sourceMessage         = "previous and next requirement source snapshots must pass source admission"
	latticeMessage        = "requirement lifecycle transitions must preserve durable records and replacement traceability"
	latticeSkippedMessage = "record-level lifecycle checks require admitted comparable requirement source snapshots"
)

var boundaryNonClaims = []string{
	"Requirement source transition admission does not approve permanent deletion of retired requirement records.",
	"Requirement source transition admission does not decide merge, release, rollout, or freshness.",
	"Requirement source transition admission does not execute proof bindings or native witnesses.",
	"Requirement source transition admission does not own requirement meaning.",
	"Requirement source transition admission does not prove replacement semantic equivalence.",
}

type admittedInput struct {
	Next         map[string]any
	NonClaims    []string
	Previous     map[string]any
	TransitionID string
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	previousResult, err := requirementsourceadmission.Evaluate(input.Previous)
	if err != nil {
		return report.Record{}, 1, err
	}
	nextResult, err := requirementsourceadmission.Evaluate(input.Next)
	if err != nil {
		return report.Record{}, 1, err
	}
	sourceFailures := []string{}
	for _, failure := range previousResult.Failures {
		sourceFailures = append(sourceFailures, "previous source admission failed: "+failure)
	}
	for _, failure := range nextResult.Failures {
		sourceFailures = append(sourceFailures, "next source admission failed: "+failure)
	}
	boundaryFailures := sourceBoundaryFailures(previousResult.Summary, nextResult.Summary)
	recordFailures := []string{}
	if len(sourceFailures) == 0 && len(boundaryFailures) == 0 {
		recordFailures = recordTransitionFailures(previousResult.Source, nextResult.Source)
	}
	failures := append(append(append([]string{}, sourceFailures...), boundaryFailures...), recordFailures...)
	sort.Strings(failures)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append(append([]string{}, boundaryNonClaims...), input.NonClaims...)
	sort.Strings(nonClaims)
	sourcePaths := []string{
		requirementsourceadmission.RequirementsPath(previousResult.Summary.SpecPackagePath),
		previousResult.Summary.SpecPackagePath,
		requirementsourceadmission.RequirementsPath(nextResult.Summary.SpecPackagePath),
		nextResult.Summary.SpecPackagePath,
	}
	sort.Strings(sourcePaths)
	record := report.Record{
		SchemaVersion: outputSchemaVersion,
		ReportKind:    reportKind,
		ReportID:      input.TransitionID,
		State:         state,
		Summary:       transitionResultSummary(previousResult, nextResult, failures),
		Diagnostics: []report.Diagnostic{
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
			{Key: "sourcePaths", Value: admit.StringSliceToAny(sourcePaths)},
		},
		RuleResults: transitionRuleResults(sourceFailures, boundaryFailures, recordFailures),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	if err := transitionOutputShape.CheckGenerated(record.JSONValue(), "requirement source transition output"); err != nil {
		return report.Record{}, 1, err
	}
	if state == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}

func admitInput(raw any) (admittedInput, error) {
	value, err := transitionInputShape.Admit(raw, "requirement source transition input")
	if err != nil {
		return admittedInput{}, err
	}
	record := value.(map[string]any)
	nonClaims, err := textArray(record["nonClaims"], "requirement source transition nonClaims")
	if err != nil {
		return admittedInput{}, err
	}
	transitionID, err := admit.RuleID(record["transitionId"], "requirement source transitionId")
	if err != nil {
		return admittedInput{}, err
	}
	previous := record["previous"].(map[string]any)
	next := record["next"].(map[string]any)
	return admittedInput{Next: next, NonClaims: nonClaims, Previous: previous, TransitionID: transitionID}, nil
}

func sourceBoundaryFailures(previous requirementsourcemodel.AssessmentSummary, next requirementsourcemodel.AssessmentSummary) []string {
	failures := []string{}
	if previous.SourceID != next.SourceID {
		failures = append(failures, "transition must compare the same requirement sourceId")
	}
	if previous.SpecPackagePath != next.SpecPackagePath {
		failures = append(failures, "transition must compare the same specPackagePath")
		failures = append(failures, "transition must compare the same overviewPath")
		failures = append(failures, "transition must compare the same requirementsPath")
	}
	return failures
}

func transitionResultSummary(previous, next requirementsourceadmission.Result, failures []string) map[string]any {
	if previous.ExitCode == 0 && next.ExitCode == 0 {
		return transitionSummary(previous.Source, next.Source, failures)
	}
	return map[string]any{
		"addedRequirementCount": nil, "lifecycleChangedRequirementCount": nil, "missingRequirementCount": nil,
		"nextRequirementCount": next.Summary.RequirementCount, "previousRequirementCount": previous.Summary.RequirementCount,
		"failureCount": len(failures),
	}
}

func recordTransitionFailures(previous requirementsourceadmission.Source, next requirementsourceadmission.Source) []string {
	failures := []string{}
	previousByID := requirementMap(previous.Requirements())
	nextByID := requirementMap(next.Requirements())
	for _, previousRequirement := range previous.Requirements() {
		nextRequirement, ok := nextByID[previousRequirement.RequirementID]
		if !ok {
			failures = append(failures, fmt.Sprintf("durable requirement must remain in next source before deletion: %s", previousRequirement.RequirementID))
			continue
		}
		failures = append(failures, requirementTransitionFailures(previousRequirement, nextRequirement, nextByID)...)
	}
	for _, nextRequirement := range next.Requirements() {
		if _, ok := previousByID[nextRequirement.RequirementID]; !ok && nextRequirement.Lifecycle.State != "active" {
			failures = append(failures, fmt.Sprintf("new requirement must start with active lifecycle: %s", nextRequirement.RequirementID))
		}
	}
	return failures
}

func requirementTransitionFailures(previous requirementsourceadmission.Requirement, next requirementsourceadmission.Requirement, nextByID map[string]requirementsourceadmission.Requirement) []string {
	failures := []string{}
	if isTerminal(previous.Lifecycle.State) && next.Lifecycle.State != previous.Lifecycle.State {
		failures = append(failures, fmt.Sprintf("terminal requirement lifecycle must not change: %s", previous.RequirementID))
	}
	if previous.Lifecycle.State == "superseded" && next.Lifecycle.State == "superseded" && !sameStringArray(previous.Lifecycle.ReplacementRequirementIDs, next.Lifecycle.ReplacementRequirementIDs) {
		failures = append(failures, fmt.Sprintf("terminal superseded replacementRequirementIds must not change: %s", previous.RequirementID))
	}
	if previous.Lifecycle.State == "active" && next.Lifecycle.State == "deprecated" {
		requireLifecycleEvidenceDelta(previous, next, &failures, "deprecated requirement transition must declare new lifecycle evidenceRefs")
	}
	if (previous.Lifecycle.State == "active" || previous.Lifecycle.State == "deprecated") && next.Lifecycle.State == "removed" {
		requireLifecycleEvidenceDelta(previous, next, &failures, "removed requirement transition must declare new lifecycle evidenceRefs")
	}
	if (previous.Lifecycle.State == "active" || previous.Lifecycle.State == "deprecated") && next.Lifecycle.State == "superseded" {
		requireLifecycleEvidenceDelta(previous, next, &failures, "superseded requirement transition must declare new lifecycle evidenceRefs")
		for _, replacementID := range next.Lifecycle.ReplacementRequirementIDs {
			replacement, ok := nextByID[replacementID]
			if !ok || replacement.Lifecycle.State != "active" {
				failures = append(failures, fmt.Sprintf("superseded requirement replacement must be active in next source: %s -> %s", next.RequirementID, replacementID))
			}
		}
	}
	if previous.Lifecycle.State == "deprecated" && next.Lifecycle.State == "active" {
		requireLifecycleEvidenceDelta(previous, next, &failures, "reactivated requirement transition must declare new lifecycle evidenceRefs")
	}
	failures = append(failures, missingStableRefs(previous.Lifecycle.EvidenceRefs, next.Lifecycle.EvidenceRefs, fmt.Sprintf("lifecycle evidenceRefs must preserve prior refs: %s", previous.RequirementID))...)
	failures = append(failures, missingStableRefs(previous.Lifecycle.ReplacementRequirementIDs, next.Lifecycle.ReplacementRequirementIDs, fmt.Sprintf("replacementRequirementIds must preserve prior refs: %s", previous.RequirementID))...)
	return failures
}

func requireLifecycleEvidenceDelta(previous requirementsourceadmission.Requirement, next requirementsourceadmission.Requirement, failures *[]string, message string) {
	if len(addedStableRefs(previous.Lifecycle.EvidenceRefs, next.Lifecycle.EvidenceRefs)) == 0 {
		*failures = append(*failures, fmt.Sprintf("%s: %s", message, next.RequirementID))
	}
}

func addedStableRefs(previousRefs []string, nextRefs []string) []string {
	previousSet := map[string]struct{}{}
	for _, ref := range previousRefs {
		previousSet[ref] = struct{}{}
	}
	added := []string{}
	for _, ref := range nextRefs {
		if _, ok := previousSet[ref]; !ok {
			added = append(added, ref)
		}
	}
	return added
}

func missingStableRefs(previousRefs []string, nextRefs []string, message string) []string {
	nextSet := map[string]struct{}{}
	for _, ref := range nextRefs {
		nextSet[ref] = struct{}{}
	}
	missing := []string{}
	for _, ref := range previousRefs {
		if _, ok := nextSet[ref]; !ok {
			missing = append(missing, fmt.Sprintf("%s missing %s", message, ref))
		}
	}
	return missing
}

func transitionSummary(previous requirementsourceadmission.Source, next requirementsourceadmission.Source, failures []string) map[string]any {
	previousByID := requirementMap(previous.Requirements())
	addedRequirementCount := 0
	lifecycleChangedRequirementCount := 0
	for _, nextRequirement := range next.Requirements() {
		previousRequirement, ok := previousByID[nextRequirement.RequirementID]
		if !ok {
			addedRequirementCount++
			continue
		}
		if previousRequirement.Lifecycle.State != nextRequirement.Lifecycle.State {
			lifecycleChangedRequirementCount++
		}
	}
	nextIDs := map[string]struct{}{}
	for _, requirement := range next.Requirements() {
		nextIDs[requirement.RequirementID] = struct{}{}
	}
	missingRequirementCount := 0
	for _, requirement := range previous.Requirements() {
		if _, ok := nextIDs[requirement.RequirementID]; !ok {
			missingRequirementCount++
		}
	}
	return map[string]any{
		"addedRequirementCount":            addedRequirementCount,
		"failureCount":                     len(failures),
		"lifecycleChangedRequirementCount": lifecycleChangedRequirementCount,
		"missingRequirementCount":          missingRequirementCount,
		"nextRequirementCount":             next.RequirementCount(),
		"previousRequirementCount":         previous.RequirementCount(),
	}
}

func transitionRuleResults(sourceFailures []string, boundaryFailures []string, recordFailures []string) []report.RuleResult {
	latticeSkipped := len(sourceFailures) > 0 || len(boundaryFailures) > 0
	latticeStatus := "passed"
	message := latticeMessage
	if latticeSkipped {
		latticeStatus = "skipped"
		message = latticeSkippedMessage
	} else if len(recordFailures) > 0 {
		latticeStatus = "failed"
	}
	return []report.RuleResult{
		{
			RuleID:      boundaryRuleID,
			Status:      statusFailedIf(len(boundaryFailures) > 0),
			Message:     boundaryMessage,
			Diagnostics: failureDiagnostics(boundaryFailures),
		},
		{
			RuleID:      sourceRuleID,
			Status:      statusFailedIf(len(sourceFailures) > 0),
			Message:     sourceMessage,
			Diagnostics: failureDiagnostics(sourceFailures),
		},
		{
			RuleID:      latticeRuleID,
			Status:      latticeStatus,
			Message:     message,
			Diagnostics: failureDiagnostics(recordFailures),
		},
	}
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

func statusFailedIf(value bool) string {
	if value {
		return "failed"
	}
	return "passed"
}

func requirementMap(requirements []requirementsourceadmission.Requirement) map[string]requirementsourceadmission.Requirement {
	result := map[string]requirementsourceadmission.Requirement{}
	for _, requirement := range requirements {
		result[requirement.RequirementID] = requirement
	}
	return result
}

func sameStringArray(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index, value := range left {
		if value != right[index] {
			return false
		}
	}
	return true
}

func isTerminal(state string) bool {
	return state == "removed" || state == "superseded"
}

func textArray(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := admit.NonEmptyText(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	return result, nil
}
