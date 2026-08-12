package requirementsourcemodel

import (
	"reflect"
	"strings"
	"testing"
)

func TestExpandedProjectionBudgetMatchesIndependentMaterialization(t *testing.T) {
	draft := validDraft()
	model, err := Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}

	estimated, itemOverflow, textOverflow := estimateExpandedProjectionCost(draft)
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
