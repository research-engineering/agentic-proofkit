package nativeevidenceguidance

import (
	"bytes"
	"encoding/json"
	"maps"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestReferenceShapeMatchesExactNativeReference(t *testing.T) {
	shape, err := ReferenceShape()
	if err != nil {
		t.Fatal(err)
	}
	reference, err := GuidanceReference()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := stablejson.Marshal(reference.JSONValue())
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := shape.Admit(value, "reference"); err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitReference(value); err != nil {
		t.Fatal(err)
	}
	original := value.(map[string]any)
	for _, field := range []string{"commandId", "contentSha256", "guidanceId", "slotCount"} {
		neighbors := []any{nil, false, "foreign"}
		if field == "slotCount" {
			neighbors = append(neighbors, json.Number("21"), json.Number("23"), json.Number("22.5"), "22")
		} else {
			neighbors = append(neighbors, original[field].(string)+" ", "")
		}
		for _, neighbor := range neighbors {
			changed := maps.Clone(original)
			changed[field] = neighbor
			assertReferenceNeighborRejected(t, shape, changed, field)
		}
		missing := maps.Clone(original)
		delete(missing, field)
		assertReferenceNeighborRejected(t, shape, missing, field)
	}
	extra := maps.Clone(original)
	extra["unexpected"] = true
	assertReferenceNeighborRejected(t, shape, extra, "unexpected")
	schema := shape.JSONSchema()
	schema["properties"].(map[string]any)["slotCount"] = nil
	fresh, err := ReferenceShape()
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.CheckGenerated(reference.JSONValue(), "fresh reference"); err != nil {
		t.Fatalf("schema projection leaked mutable state: %v", err)
	}
}

func assertReferenceNeighborRejected(t *testing.T, shape jsonshape.Shape, value map[string]any, field string) {
	t.Helper()
	if _, err := shape.Admit(value, "reference"); err == nil {
		t.Fatalf("shape accepted changed %s", field)
	}
	if _, err := AdmitReference(value); err == nil {
		t.Fatalf("native owner accepted changed %s", field)
	}
}
