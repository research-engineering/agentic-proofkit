package completioncriteria

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.completion-criteria"

var criterionClasses = map[string]struct{}{
	"advisory": {},
	"blocking": {},
	"deferred": {},
}

var criterionStatuses = map[string]struct{}{
	"advisory_skipped":             {},
	"blocked_missing_precondition": {},
	"deferred_admitted":            {},
	"failed":                       {},
	"missing_evidence":             {},
	"not_applicable":               {},
	"satisfied":                    {},
}

var satisfyingStatuses = map[string]struct{}{
	"not_applicable": {},
	"satisfied":      {},
}

var boundaryNonClaims = []any{
	"Completion criteria reports do not execute validators or native proofs.",
	"Completion criteria reports do not authenticate evidence or receipts.",
	"Completion criteria reports do not compute proof freshness.",
	"Completion criteria reports do not own requirement meaning, proof adequacy, or consumer policy.",
	"Completion criteria reports do not approve merge, release, rollout, or production readiness.",
}

type criterionInput struct {
	Blocker                *string
	Criterion              string
	CriterionClass         string
	CriterionID            string
	EvidenceRefs           []string
	FailsWhen              []string
	NonClaims              []string
	Owner                  string
	ProofRefs              []string
	Status                 string
	StructuredDecisionRefs []string
	ValidatorRefs          []string
}

type criterion struct {
	criterionInput
	BlocksCompletion bool
}

type admittedInput struct {
	CompletionID string
	Criteria     []criterionInput
	NonClaims    []any
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	criteria := make([]criterion, 0, len(input.Criteria))
	for _, item := range input.Criteria {
		_, satisfying := satisfyingStatuses[item.Status]
		criteria = append(criteria, criterion{
			criterionInput:   item,
			BlocksCompletion: item.CriterionClass == "blocking" && !satisfying,
		})
	}
	blockingUnsatisfied := []string{}
	for _, item := range criteria {
		if item.BlocksCompletion {
			blockingUnsatisfied = append(blockingUnsatisfied, item.CriterionID)
		}
	}
	state := "passed"
	if len(blockingUnsatisfied) > 0 {
		state = "failed"
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.CompletionID,
		State:         state,
		Summary: map[string]any{
			"advisoryCriterionCount":   countClass(criteria, "advisory"),
			"blockingCriterionCount":   countClass(criteria, "blocking"),
			"blockingUnsatisfiedCount": len(blockingUnsatisfied),
			"criterionCount":           len(criteria),
			"deferredCriterionCount":   countClass(criteria, "deferred"),
			"statusCounts":             statusCounts(criteria),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "blockingUnsatisfiedCriterionIds", Value: admit.StringSliceToAny(blockingUnsatisfied)},
			{Key: "criteria", Value: criteriaJSON(criteria)},
		},
		RuleResults: ruleResults(criteria),
		NonClaims:   input.NonClaims,
	}
	if state == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("completion criteria input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"completionId", "criteria", "nonClaims", "schemaVersion"}, "completion criteria input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("completion criteria schemaVersion must be 1")
	}
	completionID, err := admit.RuleID(record["completionId"], "completion criteria completionId")
	if err != nil {
		return admittedInput{}, err
	}
	criteria, err := criteriaArray(record["criteria"])
	if err != nil {
		return admittedInput{}, err
	}
	nonClaimsRaw, err := admit.TextArray(record["nonClaims"], "completion criteria nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := admit.SortedText(append(admit.AnySliceToString(boundaryNonClaims), nonClaimsRaw...), "completion criteria nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		CompletionID: completionID,
		Criteria:     criteria,
		NonClaims:    admit.StringSliceToAny(nonClaims),
	}, nil
}

func criteriaArray(raw any) ([]criterionInput, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("completion criteria criteria must be a non-empty array")
	}
	items := make([]criterionInput, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("completion criterion must be an object")
		}
		if err := admit.KnownKeys(record, []string{"blocker", "criterion", "criterionClass", "criterionId", "evidenceRefs", "failsWhen", "nonClaims", "owner", "proofRefs", "status", "structuredDecisionRefs", "validatorRefs"}, "completion criterion"); err != nil {
			return nil, err
		}
		item, err := criterionFromRecord(record)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	sort.Slice(items, func(left int, right int) bool {
		return items[left].CriterionID < items[right].CriterionID
	})
	for index := 1; index < len(items); index++ {
		if items[index-1].CriterionID == items[index].CriterionID {
			return nil, fmt.Errorf("completion criterion ids must be sorted and unique")
		}
	}
	return items, nil
}

func criterionFromRecord(record map[string]any) (criterionInput, error) {
	class, err := admit.Enum(record["criterionClass"], criterionClasses, "completion criterion criterionClass")
	if err != nil {
		return criterionInput{}, err
	}
	status, err := admit.Enum(record["status"], criterionStatuses, "completion criterion status")
	if err != nil {
		return criterionInput{}, err
	}
	evidenceRefs, err := admit.SortedTextArray(record["evidenceRefs"], "completion criterion evidenceRefs", true)
	if err != nil {
		return criterionInput{}, err
	}
	blocker, err := admit.NullableText(record["blocker"], "completion criterion blocker")
	if err != nil {
		return criterionInput{}, err
	}
	if err := validateCriterionState(class, status, evidenceRefs, blocker); err != nil {
		return criterionInput{}, err
	}
	validatorRefs, err := admit.SortedTextArray(record["validatorRefs"], "completion criterion validatorRefs", true)
	if err != nil {
		return criterionInput{}, err
	}
	proofRefs, err := admit.SortedTextArray(record["proofRefs"], "completion criterion proofRefs", true)
	if err != nil {
		return criterionInput{}, err
	}
	if len(validatorRefs) == 0 && len(proofRefs) == 0 {
		return criterionInput{}, fmt.Errorf("completion criterion must declare at least one validatorRef or proofRef")
	}
	failsWhen, err := admit.SortedTextArray(record["failsWhen"], "completion criterion failsWhen", false)
	if err != nil {
		return criterionInput{}, err
	}
	criterionID, err := admit.RuleID(record["criterionId"], "completion criterion criterionId")
	if err != nil {
		return criterionInput{}, err
	}
	criterionText, err := admit.NonEmptyText(record["criterion"], "completion criterion criterion")
	if err != nil {
		return criterionInput{}, err
	}
	owner, err := admit.NonEmptyText(record["owner"], "completion criterion owner")
	if err != nil {
		return criterionInput{}, err
	}
	structuredDecisionRefs, err := admit.SortedTextArray(record["structuredDecisionRefs"], "completion criterion structuredDecisionRefs", true)
	if err != nil {
		return criterionInput{}, err
	}
	nonClaims, err := admit.SortedTextArray(record["nonClaims"], "completion criterion nonClaims", false)
	if err != nil {
		return criterionInput{}, err
	}
	return criterionInput{
		Blocker:                blocker,
		Criterion:              criterionText,
		CriterionClass:         class,
		CriterionID:            criterionID,
		EvidenceRefs:           evidenceRefs,
		FailsWhen:              failsWhen,
		NonClaims:              nonClaims,
		Owner:                  owner,
		ProofRefs:              proofRefs,
		Status:                 status,
		StructuredDecisionRefs: structuredDecisionRefs,
		ValidatorRefs:          validatorRefs,
	}, nil
}

func validateCriterionState(class string, status string, evidenceRefs []string, blocker *string) error {
	if status == "blocked_missing_precondition" && blocker == nil {
		return fmt.Errorf("blocked completion criteria must declare blocker text")
	}
	if status != "blocked_missing_precondition" && blocker != nil {
		return fmt.Errorf("non-blocked completion criteria must not declare blocker text")
	}
	if (status == "satisfied" || status == "not_applicable") && len(evidenceRefs) == 0 {
		return fmt.Errorf("satisfied or not-applicable completion criteria must declare evidence refs")
	}
	if status == "deferred_admitted" {
		if class != "deferred" {
			return fmt.Errorf("deferred_admitted completion criteria must use deferred criterionClass")
		}
		if len(evidenceRefs) == 0 {
			return fmt.Errorf("deferred_admitted completion criteria must declare admission evidence refs")
		}
	}
	if status == "advisory_skipped" && class != "advisory" {
		return fmt.Errorf("advisory_skipped completion criteria must use advisory criterionClass")
	}
	return nil
}

func statusCounts(criteria []criterion) map[string]any {
	counts := map[string]any{
		"advisory_skipped":             0,
		"blocked_missing_precondition": 0,
		"deferred_admitted":            0,
		"failed":                       0,
		"missing_evidence":             0,
		"not_applicable":               0,
		"satisfied":                    0,
	}
	for _, item := range criteria {
		counts[item.Status] = counts[item.Status].(int) + 1
	}
	return counts
}

func countClass(criteria []criterion, class string) int {
	count := 0
	for _, item := range criteria {
		if item.CriterionClass == class {
			count++
		}
	}
	return count
}

func ruleResults(criteria []criterion) []report.RuleResult {
	results := make([]report.RuleResult, 0, len(criteria))
	for _, item := range criteria {
		status := "warning"
		if item.BlocksCompletion {
			status = "failed"
		} else if _, ok := satisfyingStatuses[item.Status]; ok {
			status = "passed"
		} else if item.Status == "advisory_skipped" || item.Status == "deferred_admitted" {
			status = "skipped"
		}
		message := fmt.Sprintf("completion criterion %s is %s", item.CriterionID, item.Status)
		if item.BlocksCompletion {
			message = fmt.Sprintf("blocking completion criterion %s is %s", item.CriterionID, item.Status)
		}
		results = append(results, report.RuleResult{
			RuleID:  fmt.Sprintf("proofkit.completion-criteria.%s", item.CriterionID),
			Status:  status,
			Message: message,
			Diagnostics: []report.Diagnostic{
				{Key: "criterion", Value: criterionJSON(item)},
			},
		})
	}
	return results
}

func criteriaJSON(criteria []criterion) []any {
	values := make([]any, 0, len(criteria))
	for _, item := range criteria {
		values = append(values, criterionJSON(item))
	}
	return values
}

func criterionJSON(item criterion) map[string]any {
	blocker := any(nil)
	if item.Blocker != nil {
		blocker = *item.Blocker
	}
	return map[string]any{
		"blocker":                blocker,
		"blocksCompletion":       item.BlocksCompletion,
		"criterion":              item.Criterion,
		"criterionClass":         item.CriterionClass,
		"criterionId":            item.CriterionID,
		"evidenceRefs":           admit.StringSliceToAny(item.EvidenceRefs),
		"failsWhen":              admit.StringSliceToAny(item.FailsWhen),
		"nonClaims":              admit.StringSliceToAny(item.NonClaims),
		"owner":                  item.Owner,
		"proofRefs":              admit.StringSliceToAny(item.ProofRefs),
		"status":                 item.Status,
		"structuredDecisionRefs": admit.StringSliceToAny(item.StructuredDecisionRefs),
		"validatorRefs":          admit.StringSliceToAny(item.ValidatorRefs),
	}
}
