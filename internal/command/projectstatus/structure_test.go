package projectstatus

import (
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func TestNavigationStructuresPreserveNativeStateActionClosure(t *testing.T) {
	for _, snapshot := range []inspectionSnapshot{
		transactionSnapshot(TransactionInvalid, ""),
		transactionSnapshot(TransactionRecoverable, digest.SHA256TextRef("transaction")),
		transactionSnapshot(TransactionClean, ""), invalidManifestSnapshot(),
		childStateSnapshot(ChildMissing), childStateSnapshot(ChildDigestMismatch),
		mixedInvalidSnapshot(), closureSnapshot(ClosureInvalid), closureSnapshot(ClosureAdmitted),
	} {
		status, err := evaluate(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		next, err := NextFromStatus(status)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range []struct {
			shape jsonshape.Shape
			value map[string]any
			keys  []string
		}{
			{StatusOutputShape(), status.JSONValue(), []string{"issueCodes", "manifestId", "nextAction", "nonClaims", "projectId", "projectState", "reportKind", "schemaVersion", "snapshotId", "statusId"}},
			{NextOutputShape(), next.JSONValue(), []string{"action", "issueCodes", "nonClaims", "packetId", "packetKind", "projectState", "schemaVersion", "snapshotId", "statusRef"}},
		} {
			if !slices.Equal(slices.Sorted(maps.Keys(row.value)), row.keys) {
				t.Fatal("native navigation field inventory differs")
			}
			if _, err := row.shape.Admit(row.value, "navigation"); err != nil {
				t.Fatal(err)
			}
			for _, key := range row.keys {
				missing := maps.Clone(row.value)
				delete(missing, key)
				if _, err := row.shape.Admit(missing, "navigation"); err == nil {
					t.Fatalf("accepted missing field %s", key)
				}
			}
			unknown := maps.Clone(row.value)
			unknown["foreign"] = true
			if _, err := row.shape.Admit(unknown, "navigation"); err == nil {
				t.Fatal("accepted unowned field")
			}
		}
	}
}

func TestNavigationStructureDoesNotGrantNativeAdmission(t *testing.T) {
	status, err := evaluate(closureSnapshot(ClosureAdmitted))
	if err != nil {
		t.Fatal(err)
	}
	next, err := NextFromStatus(status)
	if err != nil {
		t.Fatal(err)
	}
	statusValue := status.JSONValue()
	statusValue["statusId"] = digest.SHA256TextRef("wrong content")
	if _, err := StatusOutputShape().Admit(statusValue, "navigation"); err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitStatusOutput(statusValue); err == nil {
		t.Fatal("structural success replaced content identity admission")
	}
	nextValue := next.JSONValue()
	nextValue["action"].(map[string]any)["actionClass"] = ActionChooseAdoptionMode
	if _, err := NextOutputShape().Admit(nextValue, "navigation"); err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitNextOutput(nextValue); err == nil {
		t.Fatal("structural success replaced state/action admission")
	}

	before := StatusOutputStructure()
	before["properties"].(map[string]any)["nextAction"].(map[string]any)["foreign"] = true
	if reflect.DeepEqual(before, StatusOutputStructure()) {
		t.Fatal("navigation schemas share mutable derived maps")
	}
}
