package repositorytransaction

import (
	"context"
	"encoding/json"
	"maps"
	"strings"
	"testing"
)

func TestTransactionStructuresPreservePublicVersionsAndNoPayload(t *testing.T) {
	_, fixtures := loadPredecessorVectors(t)
	for _, fixture := range fixtures {
		value := decodePredecessorObject(t, fixture.Plan)
		if _, err := PlanShape().Admit(value, "v1 plan"); err != nil {
			t.Fatal(err)
		}
	}
	for _, absent := range []bool{false, true} {
		root := t.TempDir()
		target := Target{Path: "nested/record.json", Content: []byte("desired\n"), Mode: 0o644}
		if absent {
			target = Target{Path: "nested/record.json", Absent: true}
		}
		plan, err := BuildPlan(context.Background(), root, []Target{target})
		if err != nil {
			t.Fatal(err)
		}
		versions := []json.Number{"3"}
		if absent {
			versions = append(versions, "2")
		}
		for _, version := range versions {
			candidate := clonePlan(plan)
			candidate.version = version
			refreshPlanIdentity(t, &candidate)
			value := candidate.JSONValue()
			if _, err := AdmitPlanOutput(value); err != nil {
				t.Fatal(err)
			}
			if err := PlanShape().CheckGenerated(value, "plan"); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"payload", "afterContent", "beforeContent", "constructedTransactionId"} {
				extra := maps.Clone(value)
				extra[field] = "not public"
				if err := PlanShape().CheckGenerated(extra, "plan"); err == nil {
					t.Fatalf("accepted private member %s", field)
				}
			}
		}
	}
}

func TestSnapshotStructurePreservesBothPartitionsAndExactBounds(t *testing.T) {
	sha := "sha256:" + strings.Repeat("a", 64)
	shape := snapshotShape()
	absent := map[string]any{"byteCount": json.Number("0"), "exists": false, "mode": "0000", "sha256": nil}
	if _, err := shape.Admit(absent, "absent"); err != nil {
		t.Fatal(err)
	}
	if _, err := admitSnapshot(absent, "absent"); err != nil {
		t.Fatal(err)
	}
	wrongAbsent := maps.Clone(absent)
	wrongAbsent["exists"] = true
	if _, err := shape.Admit(wrongAbsent, "absent"); err == nil {
		t.Fatal("absent partition accepted opposite exists boolean")
	}
	for _, length := range []json.Number{"0", "1048576"} {
		for _, mode := range []string{"0400", "0777"} {
			present := map[string]any{"byteCount": length, "exists": true, "mode": mode, "sha256": sha}
			if _, err := shape.Admit(present, "present"); err != nil {
				t.Fatal(err)
			}
			if _, err := admitSnapshot(present, "present"); err != nil {
				t.Fatal(err)
			}
			for field, neighbors := range map[string][]any{
				"byteCount": {json.Number("-1"), json.Number("1048577"), json.Number("0.5"), "0", nil},
				"exists":    {false, json.Number("1"), "true", nil},
				"mode":      {"0000", "0300", "0408", "1400", "400", "0400 ", nil},
				"sha256":    {nil, "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("g", 64), "sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("a", 65)},
			} {
				for _, neighbor := range neighbors {
					changed := maps.Clone(present)
					changed[field] = neighbor
					if _, err := shape.Admit(changed, "snapshot"); err == nil {
						t.Fatalf("accepted invalid snapshot %s", field)
					}
					if _, err := admitSnapshot(changed, "snapshot"); err == nil {
						t.Fatalf("native accepted invalid snapshot %s", field)
					}
				}
			}
		}
	}
	for field, nonzero := range map[string]any{"byteCount": json.Number("1"), "mode": "0400", "sha256": sha} {
		changed := maps.Clone(absent)
		changed[field] = nonzero
		if _, err := shape.Admit(changed, "absent"); err == nil {
			t.Fatalf("accepted nonzero absent %s", field)
		}
	}
}

func TestTransactionStructureEnumMembership(t *testing.T) {
	operations, _ := PlanShape().Property("operations")
	operation, _ := operations.Element()
	action, _ := operation.Property("action")
	for _, value := range []string{"create", "replace", "delete", "unchanged"} {
		if _, err := action.Admit(value, "action"); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []any{"foreign", "create ", "", nil, false} {
		if _, err := action.Admit(value, "action"); err == nil {
			t.Fatal("accepted invalid action enum member")
		}
	}
	recoveredBy, _ := ResultShape().Property("recoveredBy")
	for _, value := range []any{nil, "resume", "rollback"} {
		if _, err := recoveredBy.Admit(value, "recoveredBy"); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []any{"foreign", "resume ", "", false} {
		if _, err := recoveredBy.Admit(value, "recoveredBy"); err == nil {
			t.Fatal("accepted invalid recoveredBy enum member")
		}
	}
}

func TestResultStructurePreservesAllNativeStatesAndNullableCount(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	results := []Result{
		{AppliedCount: 1, AppliedCountKnown: true, State: StateApplied, TransactionID: id},
		{AppliedCount: 32, AppliedCountKnown: true, State: StateApplied, TransactionID: id},
		{AppliedCountKnown: true, State: StateAlreadySatisfied, TransactionID: id},
		{AppliedCountKnown: true, RecoveredBy: RecoveryRollback, State: StateRolledBack, TransactionID: id},
		{FailureClass: "cleanup_failed", State: StateCleanupRequired, TransactionID: id},
		{FailureClass: "durability_unknown", State: StateDurabilityUnknown, TransactionID: id},
		{FailureClass: "ambiguous_state", State: StateRecoveryRequired},
	}
	for _, result := range results {
		value := result.JSONValue()
		if err := ResultShape().CheckGenerated(value, "result"); err != nil {
			t.Fatal(err)
		}
		if _, err := AdmitResultOutput(value); err != nil {
			t.Fatal(err)
		}
		for field := range value {
			missing := maps.Clone(value)
			delete(missing, field)
			if err := ResultShape().CheckGenerated(missing, "result"); err == nil {
				t.Fatalf("accepted missing %s", field)
			}
		}
		for _, count := range []any{json.Number("-1"), json.Number("33"), json.Number("0.5"), "0"} {
			changed := maps.Clone(value)
			changed["appliedCount"] = count
			if err := ResultShape().CheckGenerated(changed, "result"); err == nil {
				t.Fatal("accepted invalid appliedCount")
			}
		}
	}
}
