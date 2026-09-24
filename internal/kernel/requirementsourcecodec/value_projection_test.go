package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestValueProjectionPreservesCompleteModelAndCanonicalBytes(t *testing.T) {
	model := mustModel(t)
	want, err := Format(model)
	if err != nil {
		t.Fatal(err)
	}
	value, err := Value(model)
	if err != nil {
		t.Fatal(err)
	}
	if value["schemaVersion"] != json.Number("2") {
		t.Fatalf("projected version is not a canonical JSON number: %#v", value["schemaVersion"])
	}
	assessed, err := AssessValue(value)
	if err != nil {
		t.Fatal(err)
	}
	readmitted, ok := assessed.Model()
	if !ok || !projectionsEqual(model, readmitted) {
		t.Fatal("embedded value lost an owner projection")
	}
	got, err := Format(readmitted)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("value round trip changed canonical source bytes: %v", err)
	}
	value["sourceId"] = "changed.source"
	value["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)["statementCompletion"] = "changed"
	after, err := Format(model)
	if err != nil || !bytes.Equal(after, want) {
		t.Fatalf("mutating embedded value changed source model: %v", err)
	}
}

func TestValueProjectionRejectsUnadmittedModel(t *testing.T) {
	value, err := Value(requirementsourcemodel.Model{})
	if err == nil || value != nil {
		t.Fatalf("zero model projected as an admitted document: value=%#v error=%v", value, err)
	}
}
