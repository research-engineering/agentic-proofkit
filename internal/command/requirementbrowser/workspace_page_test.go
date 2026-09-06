package requirementbrowser

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestWorkspacePageByteLimitPreservesExactPrefixAndProbeBound(t *testing.T) {
	visits := []int{}
	page := workspacePage{
		Count: 5, Limit: 5, RowsKey: "rows",
		Row: func(index int) map[string]any {
			visits = append(visits, index)
			return map[string]any{"label": strings.Repeat(string(rune('A'+index)), 64)}
		},
		Projection: func(rows []any) (map[string]any, string) {
			return map[string]any{"available": 5, "rows": rows, "selected": len(rows)}, "partial_with_omissions"
		},
	}
	expected := `{"projection":{"available":5,"rows":[{"label":"` + strings.Repeat("A", 64) + `"},{"label":"` + strings.Repeat("B", 64) + `"}],"selected":2},"requestId":"page.test","schemaVersion":2,"snapshotId":"snapshot.test","state":"partial_with_omissions"}` + "\n"
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

func TestWorkspacePageOffsetDoesNotMaterializeExcludedRows(t *testing.T) {
	visits := []int{}
	page := workspacePage{
		Count: 100, Offset: 98, Limit: 10, RowsKey: "rows",
		Row: func(index int) map[string]any {
			visits = append(visits, index)
			return map[string]any{"position": index}
		},
		Projection: func(rows []any) (map[string]any, string) {
			return map[string]any{"rows": rows}, "partial_with_omissions"
		},
	}
	if _, err := page.encode("page.test", "snapshot.test", 4096); err != nil {
		t.Fatal(err)
	}
	if len(visits) != 2 || visits[0] != 98 || visits[1] != 99 {
		t.Fatalf("offset window materialized excluded rows: %v", visits)
	}
}
