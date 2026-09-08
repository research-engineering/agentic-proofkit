package requirementsourcemodel

import (
	"reflect"
	"strings"
	"testing"
)

func TestExpandedProjectionBudgetMatchesIndependentMaterialization(t *testing.T) {
	assertExpandedProjectionBudgets(t, validDraft())
}

func TestExpandedProjectionIgnoresAbsentPayloadBeforeAdmission(t *testing.T) {
	draft := validDraft()
	draft.Groups[0].Members[0].Fields.NonClaims = Field[[]string]{}
	before, _, _ := estimateExpandedProjectionCost(draft, DefaultLimits())
	draft.Groups[0].Members[0].Fields.NonClaims.Value = make([]string, 1000)
	after, _, _ := estimateExpandedProjectionCost(draft, DefaultLimits())
	if before != after {
		t.Fatal("absent metadata payload contributed to expanded cost")
	}
	if _, err := Normalize(draft); ErrorCode(err) != "hidden_field_payload" {
		t.Fatalf("hidden payload must still be rejected: %v", err)
	}
}

func TestProjectionBudgetStopsPayloadWorkButPreservesItemPrecedence(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxExpandedItems = 4
	limits.MaxExpandedTextBytes = 1
	budget := projectionBudget{limits: limits}
	budget.texts([]string{"first", "second", "third"})
	if !budget.itemOverflow || budget.cost.TextBytes != 0 || budget.textOverflow {
		t.Fatal("collection cardinality did not dominate payload traversal")
	}

	budget = projectionBudget{limits: limits}
	budget.text("first")
	if !budget.textOverflow || budget.itemOverflow || budget.cost.Items != 2 {
		t.Fatal("text-only overflow did not preserve item accounting")
	}
	bytes := budget.cost.TextBytes
	budget.texts([]string{"second", "third"})
	if !budget.itemOverflow || budget.cost.TextBytes != bytes {
		t.Fatal("text overflow either suppressed item accounting or continued text work")
	}
	if err := preflightExpandedProjectionBudget(validDraft(), limits); ErrorCode(err) != "expanded_item_budget_exceeded" {
		t.Fatalf("item overflow must dominate text overflow: %v", err)
	}
}

func TestExpandedBudgetRejectsRepeatedProfileBeforeSemanticWork(t *testing.T) {
	draft := validDraft()
	moveMetadataFieldToOtherOwner(&draft, "nonClaims")
	draft.Profiles[0].Fields.NonClaims.Value = make([]string, 1024)
	for index := range draft.Profiles[0].Fields.NonClaims.Value {
		draft.Profiles[0].Fields.NonClaims.Value[index] = "Boundary statement."
	}
	// Repetition is invalid, but the expanded budget must reject it before
	// per-statement semantics or repeated materialization can become the guard.
	limits := DefaultLimits()
	limits.MaxExpandedItems = 2048
	if _, err := NormalizeWithLimits(draft, limits); ErrorCode(err) != "expanded_item_budget_exceeded" {
		t.Fatalf("expanded profile was processed before its budget: %v", err)
	}
}

func assertExpandedProjectionBudgets(t *testing.T, draft Draft) {
	t.Helper()
	model, err := Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}

	estimated, itemOverflow, textOverflow := estimateExpandedProjectionCost(draft, DefaultLimits())
	if itemOverflow || textOverflow {
		t.Fatalf("valid fixture overflowed estimate: item=%t text=%t", itemOverflow, textOverflow)
	}
	observed := observeStructuredCost(model.Atomic(), model.Layout(), model.References())
	const observedMaterializations = 2
	if materializationCopies != observedMaterializations {
		t.Fatalf("materialization copies = %d, want %d", materializationCopies, observedMaterializations)
	}
	observed.Items *= observedMaterializations
	observed.TextBytes *= observedMaterializations
	if estimated.TextBytes != observed.TextBytes {
		t.Fatalf("estimated text bytes = %d, observed = %d", estimated.TextBytes, observed.TextBytes)
	}
	if estimated.Items != observed.Items {
		t.Fatalf("estimated items = %d, observed = %d", estimated.Items, observed.Items)
	}

	limits := DefaultLimits()
	limits.MaxExpandedItems = int(estimated.Items)
	limits.MaxExpandedTextBytes = int(estimated.TextBytes)
	if _, err := NormalizeWithLimits(draft, limits); err != nil {
		t.Fatalf("exact expanded budgets rejected: %v", err)
	}

	itemLimits := DefaultLimits()
	itemLimits.MaxExpandedItems = int(estimated.Items - 1)
	if _, err := NormalizeWithLimits(draft, itemLimits); ErrorCode(err) != "expanded_item_budget_exceeded" {
		t.Fatalf("item limit-1 ErrorCode() = %q, error = %v", ErrorCode(err), err)
	}
	textLimits := DefaultLimits()
	textLimits.MaxExpandedTextBytes = int(estimated.TextBytes - 1)
	if _, err := NormalizeWithLimits(draft, textLimits); ErrorCode(err) != "expanded_text_budget_exceeded" {
		t.Fatalf("text limit-1 ErrorCode() = %q, error = %v", ErrorCode(err), err)
	}
}

func TestBoundaryMetadataBudgetsCoverBothLexicalOwners(t *testing.T) {
	for _, fieldID := range []MetadataFieldID{"nonClaims", "externalNonClaimRefs", "proofBindingRefs"} {
		for _, shared := range []bool{false, true} {
			t.Run(string(fieldID)+"/"+map[bool]string{false: "member", true: "profile"}[shared], func(t *testing.T) {
				draft := validDraft()
				if shared {
					moveMetadataFieldToOtherOwner(&draft, fieldID)
				}
				assertExpandedProjectionBudgets(t, draft)
				items := observeInputCollectionItems(reflect.ValueOf(draft))
				text := observeStructuredCost(draft).TextBytes
				limits := DefaultLimits()
				limits.MaxCollectionItems, limits.MaxTotalTextBytes = int(items), int(text)
				if _, err := NormalizeWithLimits(draft, limits); err != nil {
					t.Fatalf("exact independent input budgets rejected: %v", err)
				}
				limits.MaxCollectionItems--
				if _, err := NormalizeWithLimits(draft, limits); ErrorCode(err) != "collection_item_budget_exceeded" {
					t.Fatalf("input item limit-minus-one: %v", err)
				}
				limits.MaxCollectionItems++
				limits.MaxTotalTextBytes--
				if _, err := NormalizeWithLimits(draft, limits); ErrorCode(err) != "text_budget_exceeded" {
					t.Fatalf("input byte limit-minus-one: %v", err)
				}
			})
		}
	}
}

func observeStructuredCost(values ...any) projectionCost {
	cost := projectionCost{}
	for _, value := range values {
		observeMaterializedValue(reflect.ValueOf(value), &cost)
	}
	return cost
}

func observeMaterializedValue(value reflect.Value, cost *projectionCost) {
	if !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if !value.IsNil() {
			observeMaterializedValue(value.Elem(), cost)
		}
	case reflect.Struct:
		cost.Items++
		if isPresenceField(value.Type()) {
			if value.FieldByName("Present").Bool() {
				observeMaterializedValue(value.FieldByName("Value"), cost)
			}
			return
		}
		for index := 0; index < value.NumField(); index++ {
			observeMaterializedValue(value.Field(index), cost)
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			observeMaterializedValue(value.Index(index), cost)
		}
	case reflect.Map:
		cost.Items++
		iterator := value.MapRange()
		for iterator.Next() {
			observeMaterializedValue(iterator.Key(), cost)
			observeMaterializedValue(iterator.Value(), cost)
		}
	case reflect.String:
		cost.Items++
		cost.TextBytes += uint64(len(value.String()))
	}
}

func isPresenceField(value reflect.Type) bool {
	return value.PkgPath() == reflect.TypeOf(Field[string]{}).PkgPath() && strings.HasPrefix(value.Name(), "Field[")
}
