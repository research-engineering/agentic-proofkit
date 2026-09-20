package requirementsourcemodel

import (
	"reflect"
	"testing"
)

func TestNormalizeOwnsDetachedInputAcrossCalls(t *testing.T) {
	for _, owner := range []MetadataOwnerKind{MetadataOwnerMember, MetadataOwnerProfile} {
		t.Run(string(owner), func(t *testing.T) {
			draft := validDraft()
			applyMetadataVariantForOwner(&draft, "claimLevel", string(ClaimDeferred), owner)
			model, err := Normalize(draft)
			if err != nil {
				t.Fatal(err)
			}
			atomic := detachedTestCopy(model.Atomic())
			layout := detachedTestCopy(model.Layout())
			references := detachedTestCopy(model.References())
			assertUnchanged := func(step string) {
				t.Helper()
				if !reflect.DeepEqual(model.Atomic(), atomic) || !reflect.DeepEqual(model.Layout(), layout) || !reflect.DeepEqual(model.References(), references) {
					t.Fatalf("%s changed an admitted model", step)
				}
			}
			if mutateReferencedState(reflect.ValueOf(&draft).Elem(), false) == 0 {
				t.Fatal("draft fixture did not expose mutable references")
			}
			assertUnchanged("caller mutation")
			other := validDraft()
			other.SourceID = "source.second"
			other.SourceNonClaims = []string{"A separate source boundary."}
			other.Groups[0].StatementStem = "The API must"
			if _, err := Normalize(other); err != nil {
				t.Fatal(err)
			}
			assertUnchanged("later normalization")
			assertAccessorReturnsDetachedState(t, "atomic", model.Atomic)
			assertAccessorReturnsDetachedState(t, "layout", model.Layout)
			assertAccessorReturnsDetachedState(t, "references", model.References)
		})
	}
}

func assertAccessorReturnsDetachedState[T any](t *testing.T, name string, accessor func() T) {
	t.Helper()
	baseline := detachedTestCopy(accessor())
	mutated := accessor()
	mutationCount := mutateReferencedState(reflect.ValueOf(&mutated).Elem(), false)
	if mutationCount == 0 || reflect.DeepEqual(mutated, baseline) {
		t.Fatalf("%s fixture exposes no mutable reference state", name)
	}
	if fresh := accessor(); !reflect.DeepEqual(fresh, baseline) {
		t.Fatalf("%s accessor exposed mutable owner state after %d independent mutations", name, mutationCount)
	}
}

func detachedTestCopy[T any](value T) T {
	copy := deepCopyTestValue(reflect.ValueOf(value))
	return copy.Interface().(T)
}

func deepCopyTestValue(value reflect.Value) reflect.Value {
	if !value.IsValid() {
		return value
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		result := reflect.New(value.Type()).Elem()
		result.Set(deepCopyTestValue(value.Elem()))
		return result
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		result := reflect.New(value.Type().Elem())
		result.Elem().Set(deepCopyTestValue(value.Elem()))
		return result
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		result := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for index := 0; index < value.Len(); index++ {
			result.Index(index).Set(deepCopyTestValue(value.Index(index)))
		}
		return result
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		result := reflect.MakeMapWithSize(value.Type(), value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			result.SetMapIndex(deepCopyTestValue(iterator.Key()), deepCopyTestValue(iterator.Value()))
		}
		return result
	case reflect.Struct:
		result := reflect.New(value.Type()).Elem()
		for index := 0; index < value.NumField(); index++ {
			result.Field(index).Set(deepCopyTestValue(value.Field(index)))
		}
		return result
	case reflect.Array:
		result := reflect.New(value.Type()).Elem()
		for index := 0; index < value.Len(); index++ {
			result.Index(index).Set(deepCopyTestValue(value.Index(index)))
		}
		return result
	default:
		return value
	}
}

func mutateReferencedState(value reflect.Value, behindReference bool) int {
	if !value.IsValid() {
		return 0
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return 0
		}
		copy := reflect.New(value.Elem().Type()).Elem()
		copy.Set(value.Elem())
		count := mutateReferencedState(copy, behindReference)
		if count != 0 && value.CanSet() {
			value.Set(copy)
		}
		return count
	case reflect.Pointer:
		if value.IsNil() {
			return 0
		}
		return mutateReferencedState(value.Elem(), true)
	case reflect.Slice:
		count := 0
		for index := 0; index < value.Len(); index++ {
			count += mutateReferencedState(value.Index(index), true)
		}
		return count
	case reflect.Map:
		count := 0
		iterator := value.MapRange()
		for iterator.Next() {
			entry := reflect.New(value.Type().Elem()).Elem()
			entry.Set(iterator.Value())
			entryCount := mutateReferencedState(entry, true)
			if entryCount != 0 {
				value.SetMapIndex(iterator.Key(), entry)
				count += entryCount
			}
		}
		return count
	case reflect.Struct:
		count := 0
		for index := 0; index < value.NumField(); index++ {
			count += mutateReferencedState(value.Field(index), behindReference)
		}
		return count
	case reflect.Array:
		count := 0
		for index := 0; index < value.Len(); index++ {
			count += mutateReferencedState(value.Index(index), behindReference)
		}
		return count
	case reflect.String:
		if behindReference && value.CanSet() {
			value.SetString(value.String() + ".mutated")
			return 1
		}
	case reflect.Bool:
		if behindReference && value.CanSet() {
			value.SetBool(!value.Bool())
			return 1
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if behindReference && value.CanSet() {
			value.SetInt(value.Int() + 1)
			return 1
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if behindReference && value.CanSet() {
			value.SetUint(value.Uint() + 1)
			return 1
		}
	}
	return 0
}
