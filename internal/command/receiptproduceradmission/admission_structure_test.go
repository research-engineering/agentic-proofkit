package receiptproduceradmission

import (
	"reflect"
	"testing"
)

func TestReceiptAdmissionStructuresAreDetachedFromNativePolicy(t *testing.T) {
	before, beforeCode, err := Build(validAdmission())
	if err != nil {
		t.Fatal(err)
	}
	for _, factory := range []func() map[string]any{InputStructure, OutputStructure} {
		schema, fresh := factory(), factory()
		if !reflect.DeepEqual(schema, fresh) {
			t.Fatal("unstable detached structure")
		}
		fields := schema["properties"].(map[string]any)
		delete(fields, "nonClaims")
		schema["required"] = []any{}
		if !reflect.DeepEqual(factory(), fresh) {
			t.Fatal("caller changed a shared declaration")
		}
	}
	after, afterCode, err := Build(validAdmission())
	if err != nil || beforeCode != afterCode || !reflect.DeepEqual(before.JSONValue(), after.JSONValue()) {
		t.Fatal("projection mutation changed native policy or report")
	}
}
