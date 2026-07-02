package contractenv

import "testing"

func TestObjectReturnsCanonicalSnapshot(t *testing.T) {
	type definedMap map[string]any
	type definedSlice []any
	typedMap := map[string]string{"id": "typed-owner"}
	typedList := []map[string]string{{"id": "typed-list-owner"}}
	typedStrings := []string{"first"}
	defined := definedMap{"items": definedSlice{"defined-first"}}
	raw := map[string]any{
		"schema":       "proofkit.test.v1",
		"typedMap":     typedMap,
		"typedList":    typedList,
		"typedStrings": typedStrings,
		"defined":      defined,
		"owner": map[string]any{
			"id": "proofkit.owner",
		},
		"items": []any{"first"},
	}

	record, err := Object(raw, "proofkit.test.v1", "test", "owner", "items", "typedMap", "typedList", "typedStrings", "defined")
	if err != nil {
		t.Fatalf("Object() error = %v", err)
	}
	owner, err := ObjectField(record, "owner", "test")
	if err != nil {
		t.Fatalf("ObjectField() error = %v", err)
	}

	raw["schema"] = "mutated"
	raw["owner"].(map[string]any)["id"] = "mutated"
	raw["items"].([]any)[0] = "mutated"
	typedMap["id"] = "mutated"
	typedList[0]["id"] = "mutated"
	typedStrings[0] = "mutated"
	defined["items"].(definedSlice)[0] = "mutated"
	owner["id"] = "field-mutated"

	if record["schema"] != "proofkit.test.v1" {
		t.Fatalf("record schema changed after raw mutation: %#v", record)
	}
	if got := record["owner"].(map[string]any)["id"]; got != "proofkit.owner" {
		t.Fatalf("nested owner changed after raw/field mutation: %v", got)
	}
	if got := record["items"].([]any)[0]; got != "first" {
		t.Fatalf("array item changed after raw mutation: %v", got)
	}
	if got := record["typedMap"].(map[string]string)["id"]; got != "typed-owner" {
		t.Fatalf("typed map changed after raw mutation: %v", got)
	}
	if got := record["typedList"].([]map[string]string)[0]["id"]; got != "typed-list-owner" {
		t.Fatalf("typed list changed after raw mutation: %v", got)
	}
	if got := record["typedStrings"].([]string)[0]; got != "first" {
		t.Fatalf("typed strings changed after raw mutation: %v", got)
	}
	if got := record["defined"].(map[string]any)["items"].([]any)[0]; got != "defined-first" {
		t.Fatalf("defined container changed after raw mutation: %v", got)
	}
}
