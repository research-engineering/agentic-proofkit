package adoptionchecklist

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.adoption-checklist"

var scenarios = map[string]struct{}{
	"existing_gradual_adoption": {},
	"legacy_proof_migration":    {},
	"new_repository":            {},
	"release_channel":           {},
}

var itemStatuses = map[string]struct{}{
	"blocked":        {},
	"missing":        {},
	"not_applicable": {},
	"satisfied":      {},
}

var checklistNonClaims = []any{
	"Adoption checklist reports do not authenticate evidence or receipts.",
	"Adoption checklist reports do not discover repository state.",
	"Adoption checklist reports do not execute commands.",
	"Adoption checklist reports do not own consumer repository policy.",
	"Adoption checklist reports do not prove freshness, merge readiness, release readiness, rollout readiness, or production readiness.",
}

type itemInput struct {
	Blocker      *string
	CommandRefs  []string
	EvidenceRefs []string
	ItemID       string
	Label        string
	NonClaims    []string
	Owner        string
	Status       string
}

type item struct {
	itemInput
	Required bool
}

type admittedInput struct {
	ChecklistID     string
	Items           []itemInput
	NextCommandRefs []string
	NonClaims       []string
	RequiredItemIDs []string
	Scenario        string
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	requiredSet := map[string]struct{}{}
	for _, itemID := range input.RequiredItemIDs {
		requiredSet[itemID] = struct{}{}
	}
	items := make([]item, 0, len(input.Items))
	itemIDSet := map[string]struct{}{}
	for _, inputItem := range input.Items {
		_, required := requiredSet[inputItem.ItemID]
		items = append(items, item{
			itemInput: inputItem,
			Required:  required,
		})
		itemIDSet[inputItem.ItemID] = struct{}{}
	}
	structuralFailures := []string{}
	for _, requiredItemID := range input.RequiredItemIDs {
		if _, ok := itemIDSet[requiredItemID]; !ok {
			structuralFailures = append(structuralFailures, fmt.Sprintf("required item %s must reference a declared checklist item", requiredItemID))
		}
	}
	missingRequiredItemIDs := filterRequired(items, "missing")
	blockedRequiredItemIDs := filterRequired(items, "blocked")
	notApplicableRequiredItemIDs := filterRequired(items, "not_applicable")
	failures := append([]string{}, structuralFailures...)
	for _, itemID := range missingRequiredItemIDs {
		failures = append(failures, fmt.Sprintf("required item %s is missing", itemID))
	}
	for _, itemID := range blockedRequiredItemIDs {
		failures = append(failures, fmt.Sprintf("required item %s is blocked", itemID))
	}
	for _, itemID := range notApplicableRequiredItemIDs {
		failures = append(failures, fmt.Sprintf("required item %s is not applicable", itemID))
	}
	checklistState := "passed"
	reportState := "passed"
	if len(failures) > 0 {
		checklistState = "blocked"
		reportState = "failed"
	}
	checklist := map[string]any{
		"blockedRequiredItemIds":       admit.StringSliceToAny(blockedRequiredItemIDs),
		"checklistId":                  input.ChecklistID,
		"checklistKind":                reportKind,
		"items":                        itemsJSON(items),
		"missingRequiredItemIds":       admit.StringSliceToAny(missingRequiredItemIDs),
		"nextCommandRefs":              admit.StringSliceToAny(input.NextCommandRefs),
		"nonClaims":                    admit.StringSliceToAny(input.NonClaims),
		"notApplicableRequiredItemIds": admit.StringSliceToAny(notApplicableRequiredItemIDs),
		"requiredItemIds":              admit.StringSliceToAny(input.RequiredItemIDs),
		"scenario":                     input.Scenario,
		"schemaVersion":                1,
		"state":                        checklistState,
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.ChecklistID,
		State:         reportState,
		Summary: map[string]any{
			"blockedRequiredCount":       len(blockedRequiredItemIDs),
			"itemCount":                  len(items),
			"missingRequiredCount":       len(missingRequiredItemIDs),
			"notApplicableRequiredCount": len(notApplicableRequiredItemIDs),
			"requiredItemCount":          len(input.RequiredItemIDs),
			"scenario":                   input.Scenario,
			"satisfiedRequiredCount":     countRequiredStatus(items, "satisfied"),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "checklist", Value: checklist},
		},
		RuleResults: ruleResults(failures),
		NonClaims:   admit.StringSliceToAny(input.NonClaims),
	}
	if reportState == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("adoption checklist input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"checklistId", "items", "nextCommandRefs", "nonClaims", "requiredItemIds", "scenario", "schemaVersion"}, "adoption checklist input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("adoption checklist schemaVersion must be 1")
	}
	checklistID, err := admit.RuleID(record["checklistId"], "adoption checklist checklistId")
	if err != nil {
		return admittedInput{}, err
	}
	items, err := admitItems(record["items"])
	if err != nil {
		return admittedInput{}, err
	}
	requiredItemIDs, err := ruleIDArray(record["requiredItemIds"], "adoption checklist requiredItemIds", false)
	if err != nil {
		return admittedInput{}, err
	}
	nextCommandRefs, err := textArray(record["nextCommandRefs"], "adoption checklist nextCommandRefs", true)
	if err != nil {
		return admittedInput{}, err
	}
	nonClaimsInput, err := textArray(record["nonClaims"], "adoption checklist nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims := append(admit.AnySliceToString(checklistNonClaims), nonClaimsInput...)
	sort.Strings(nonClaims)
	if err := sortedUnique(nonClaims, "adoption checklist nonClaims", false); err != nil {
		return admittedInput{}, err
	}
	scenario, err := admit.Enum(record["scenario"], scenarios, "adoption checklist scenario")
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		ChecklistID:     checklistID,
		Items:           items,
		NextCommandRefs: nextCommandRefs,
		NonClaims:       nonClaims,
		RequiredItemIDs: requiredItemIDs,
		Scenario:        scenario,
	}, nil
}

func admitItems(raw any) ([]itemInput, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("adoption checklist items must be a non-empty array")
	}
	items := make([]itemInput, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("adoption checklist item %d must be an object", index)
		}
		if err := admit.KnownKeys(record, []string{"blocker", "commandRefs", "evidenceRefs", "itemId", "label", "nonClaims", "owner", "status"}, "adoption checklist item"); err != nil {
			return nil, err
		}
		status, err := admit.Enum(record["status"], itemStatuses, "adoption checklist item status")
		if err != nil {
			return nil, err
		}
		blocker, err := admit.NullableText(record["blocker"], "adoption checklist item blocker")
		if err != nil {
			return nil, err
		}
		if status == "blocked" && blocker == nil {
			return nil, fmt.Errorf("blocked adoption checklist items must declare blocker text")
		}
		if status != "blocked" && blocker != nil {
			return nil, fmt.Errorf("non-blocked adoption checklist items must not declare blocker text")
		}
		evidenceRefs, err := textArray(record["evidenceRefs"], "adoption checklist item evidenceRefs", true)
		if err != nil {
			return nil, err
		}
		if status == "satisfied" && len(evidenceRefs) == 0 {
			return nil, fmt.Errorf("satisfied adoption checklist items must declare at least one evidence ref")
		}
		itemID, err := admit.RuleID(record["itemId"], "adoption checklist itemId")
		if err != nil {
			return nil, err
		}
		label, err := admit.NonEmptyText(record["label"], "adoption checklist item label")
		if err != nil {
			return nil, err
		}
		owner, err := admit.NonEmptyText(record["owner"], "adoption checklist item owner")
		if err != nil {
			return nil, err
		}
		commandRefs, err := textArray(record["commandRefs"], "adoption checklist item commandRefs", true)
		if err != nil {
			return nil, err
		}
		nonClaims, err := textArray(record["nonClaims"], "adoption checklist item nonClaims", false)
		if err != nil {
			return nil, err
		}
		items = append(items, itemInput{
			Blocker:      blocker,
			CommandRefs:  commandRefs,
			EvidenceRefs: evidenceRefs,
			ItemID:       itemID,
			Label:        label,
			NonClaims:    nonClaims,
			Owner:        owner,
			Status:       status,
		})
	}
	sort.Slice(items, func(left int, right int) bool {
		return items[left].ItemID < items[right].ItemID
	})
	for index := 1; index < len(items); index++ {
		if items[index-1].ItemID == items[index].ItemID {
			return nil, fmt.Errorf("adoption checklist item ids must be sorted and unique")
		}
	}
	return items, nil
}

func itemsJSON(items []item) []any {
	result := make([]any, 0, len(items))
	for _, item := range items {
		result = append(result, map[string]any{
			"blocker":      nullableStringValue(item.Blocker),
			"commandRefs":  admit.StringSliceToAny(item.CommandRefs),
			"evidenceRefs": admit.StringSliceToAny(item.EvidenceRefs),
			"itemId":       item.ItemID,
			"label":        item.Label,
			"nonClaims":    admit.StringSliceToAny(item.NonClaims),
			"owner":        item.Owner,
			"required":     item.Required,
			"status":       item.Status,
		})
	}
	return result
}

func ruleResults(failures []string) []report.RuleResult {
	if len(failures) == 0 {
		return []report.RuleResult{
			{
				Diagnostics: []report.Diagnostic{},
				Message:     "all required adoption checklist items are satisfied",
				RuleID:      "proofkit.adoption-checklist.required-items-satisfied",
				Status:      "passed",
			},
		}
	}
	results := make([]report.RuleResult, 0, len(failures))
	for index, failure := range failures {
		results = append(results, report.RuleResult{
			Diagnostics: []report.Diagnostic{},
			Message:     failure,
			RuleID:      fmt.Sprintf("proofkit.adoption-checklist.failure.%03d", index+1),
			Status:      "failed",
		})
	}
	return results
}

func filterRequired(items []item, status string) []string {
	result := []string{}
	for _, item := range items {
		if item.Required && item.Status == status {
			result = append(result, item.ItemID)
		}
	}
	return result
}

func countRequiredStatus(items []item, status string) int {
	count := 0
	for _, item := range items {
		if item.Required && item.Status == status {
			count++
		}
	}
	return count
}

func ruleIDArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		ruleID, err := admit.RuleID(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, ruleID)
	}
	sort.Strings(result)
	return result, sortedUnique(result, context, allowEmpty)
}

func textArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := admit.NonEmptyText(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	sort.Strings(result)
	return result, sortedUnique(result, context, allowEmpty)
}

func sortedUnique(values []string, context string, allowEmpty bool) error {
	if !allowEmpty && len(values) == 0 {
		return fmt.Errorf("%s must be non-empty", context)
	}
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return nil
}

func nullableStringValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
