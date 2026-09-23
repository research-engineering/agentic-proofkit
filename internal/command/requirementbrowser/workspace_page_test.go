package requirementbrowser

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestWorkspacePageByteLimitPreservesExactPrefixAndProbeBound(t *testing.T) {
	visits := []int{}
	page := workspacePage{
		Count: 5, Limit: 5, RowsKey: "rows",
		Row: func(index int) map[string]any {
			visits = append(visits, index)
			return map[string]any{"label": strings.Repeat(string(rune('A'+index)), 64)}
		},
		Projection: func(rows []any) (workspaceProjection, error) {
			return workspaceProjection{Value: map[string]any{"available": 5, "rows": rows, "selected": len(rows)}, State: "partial_with_omissions"}, nil
		},
	}
	expected := `{"projection":{"available":5,"rows":[{"label":"` + strings.Repeat("A", 64) + `"},{"label":"` + strings.Repeat("B", 64) + `"}],"selected":2},"requestId":"page.test","schemaVersion":3,"snapshotId":"snapshot.test","state":"partial_with_omissions"}` + "\n"
	body, err := page.encode("page.test", "snapshot.test", len(expected))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != expected {
		t.Fatal("exact byte-limit page differs from independently authored wire body")
	}
	if len(visits) != 3 || visits[0] != 0 || visits[1] != 1 || visits[2] != 2 {
		t.Fatalf("row work = %v, want retained rows plus one overflow probe", visits)
	}
	visits = nil
	one, err := page.encode("page.test", "snapshot.test", len(expected)-1)
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(one), int64(len(one)))
	if err != nil {
		t.Fatal(err)
	}
	projection := value.(map[string]any)["projection"].(map[string]any)
	if projection["selected"] != json.Number("1") || len(visits) != 2 {
		t.Fatal("one byte below the two-row bound did not retain one exact row")
	}
	visits = nil
	if _, err := page.encode("page.test", "snapshot.test", 1); err == nil || !strings.Contains(err.Error(), "metadata") || len(visits) != 0 {
		t.Fatal("metadata overflow did not dominate row materialization")
	}
	visits = nil
	if _, err := page.encode("page.test", "snapshot.test", 200); err == nil || !strings.Contains(err.Error(), "record") || len(visits) != 1 {
		t.Fatal("unfit first record did not fail without materializing later rows")
	}
}

func TestWorkspacePageSharedArraySizesMatchCanonicalBytes(t *testing.T) {
	text := "Restriction \U0001f9ed with \"quoted\" and \\ escaped\ntext."
	definitions := []any{map[string]any{"nonClaimId": "NCL-LOCAL", "statement": text}}
	// This independent JSON encoder agrees on the chosen scalar corpus. The
	// resulting bytes, not the page estimator, own the expected shared size.
	encodedDefinitions, err := json.Marshal(definitions)
	if err != nil {
		t.Fatal(err)
	}
	page := workspacePage{Count: 4, Limit: 4, RowsKey: "rows", Row: func(position int) map[string]any { return map[string]any{"position": position} }}
	delta := 0
	page.Projection = func(rows []any) (workspaceProjection, error) {
		values, size := []any{}, 2
		if len(rows) > 0 {
			values, size = definitions, len(encodedDefinitions)+delta
		}
		return workspaceProjection{Value: map[string]any{"rows": rows, "definitions": values}, State: "partial_with_omissions", EncodedArrayBytes: map[string]int{"definitions": size}}, nil
	}
	expected := `{"projection":{"definitions":` + string(encodedDefinitions) + `,"rows":[{"position":0},{"position":1}]},"requestId":"test.page","schemaVersion":3,"snapshotId":"test.snapshot","state":"partial_with_omissions"}` + "\n"
	body, err := page.encode("test.page", "test.snapshot", len(expected))
	if err != nil || string(body) != expected {
		t.Fatalf("independent byte oracle: %v\n%s", err, body)
	}
	for _, wrongSize := range []int{-1, 1, 1000} {
		delta = wrongSize
		if _, err := page.encode("test.page", "test.snapshot", len(expected)); err == nil || !strings.Contains(err.Error(), "disagrees") {
			t.Fatalf("incorrect shared size %d silently changed selection: %v", delta, err)
		}
	}
	delta = 0
	actual, err := stablejson.MarshalLayout(definitions, stablejson.LayoutCompact)
	if err != nil || string(actual) != string(encodedDefinitions)+"\n" {
		t.Fatal("independent encoder corpus does not agree on scalar semantics")
	}
}

func TestWorkspacePagePropagatesProjectionErrorsAndRejectsInvalidSizeKeys(t *testing.T) {
	sentinel := errors.New("projection unavailable")
	for _, after := range []int{0, 1} {
		page := workspacePage{Count: 1, Limit: 1, RowsKey: "rows", Row: func(int) map[string]any { return map[string]any{} }, Projection: func(rows []any) (workspaceProjection, error) {
			if len(rows) == after {
				return workspaceProjection{}, sentinel
			}
			return workspaceProjection{Value: map[string]any{"rows": rows}}, nil
		}}
		if _, err := page.encode("test.page", "test.snapshot", 4096); !errors.Is(err, sentinel) {
			t.Fatalf("projection error at %d was hidden: %v", after, err)
		}
	}
	for _, key := range []string{"rows", "missing", "notAnArray"} {
		page := workspacePage{RowsKey: "rows", Projection: func(rows []any) (workspaceProjection, error) {
			return workspaceProjection{Value: map[string]any{"rows": rows, "notAnArray": "text"}, EncodedArrayBytes: map[string]int{key: 2}}, nil
		}}
		if _, err := page.encode("test.page", "test.snapshot", 4096); err == nil {
			t.Fatalf("invalid size key %s admitted", key)
		}
	}
}

func TestWorkspacePageOffsetDoesNotMaterializeExcludedRows(t *testing.T) {
	visits := []int{}
	page := workspacePage{
		Count: 100, Offset: 98, Limit: 10, RowsKey: "rows",
		Row: func(index int) map[string]any {
			visits = append(visits, index)
			return map[string]any{"position": index}
		},
		Projection: func(rows []any) (workspaceProjection, error) {
			return workspaceProjection{Value: map[string]any{"rows": rows}, State: "partial_with_omissions"}, nil
		},
	}
	if _, err := page.encode("page.test", "snapshot.test", 4096); err != nil {
		t.Fatal(err)
	}
	if len(visits) != 2 || visits[0] != 98 || visits[1] != 99 {
		t.Fatalf("offset window materialized excluded rows: %v", visits)
	}
}
