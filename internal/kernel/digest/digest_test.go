package digest

import "testing"

func TestStableJSONSHA256RefIsCanonicalAndSemantic(t *testing.T) {
	left := map[string]any{
		"b": []any{"second"},
		"a": "first",
	}
	right := map[string]any{
		"a": "first",
		"b": []any{"second"},
	}
	changed := map[string]any{
		"a": "first",
		"b": []any{"changed"},
	}

	leftRef, err := StableJSONSHA256Ref(left)
	if err != nil {
		t.Fatalf("StableJSONSHA256Ref(left) error = %v", err)
	}
	rightRef, err := StableJSONSHA256Ref(right)
	if err != nil {
		t.Fatalf("StableJSONSHA256Ref(right) error = %v", err)
	}
	changedRef, err := StableJSONSHA256Ref(changed)
	if err != nil {
		t.Fatalf("StableJSONSHA256Ref(changed) error = %v", err)
	}

	if leftRef != rightRef {
		t.Fatalf("canonical refs differ: %s != %s", leftRef, rightRef)
	}
	if leftRef == changedRef {
		t.Fatalf("semantic change kept digest ref: %s", leftRef)
	}
}

func TestStableJSONSHA256RefRejectsUnsupportedValues(t *testing.T) {
	if _, err := StableJSONSHA256Ref(map[string]any{"bad": 1.25}); err == nil {
		t.Fatalf("StableJSONSHA256Ref() admitted unsupported float")
	}
}
