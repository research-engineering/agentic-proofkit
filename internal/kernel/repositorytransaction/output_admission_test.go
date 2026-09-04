package repositorytransaction

import (
	"context"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func TestPlanAndResultOutputAdmissionRejectSemanticMutants(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "proofkit/record.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	if admitted, err := AdmitPlanOutput(plan.JSONValue()); err != nil || admitted.TransactionID != plan.TransactionID {
		t.Fatalf("AdmitPlanOutput() plan=%#v error=%v", admitted, err)
	}
	planMutant := plan.JSONValue()
	planMutant["transactionId"] = "sha256:" + strings.Repeat("0", 64)
	if _, err := AdmitPlanOutput(planMutant); err == nil {
		t.Fatal("AdmitPlanOutput() admitted a forged transaction identity")
	}

	transactionID := plan.TransactionID
	results := []Result{
		{AppliedCount: 1, AppliedCountKnown: true, State: StateApplied, TransactionID: transactionID},
		{AppliedCountKnown: true, State: StateAlreadySatisfied, TransactionID: transactionID},
		{AppliedCountKnown: true, RecoveredBy: RecoveryRollback, State: StateRolledBack, TransactionID: transactionID},
		{FailureClass: "ambiguous_target_state", State: StateRecoveryRequired, TransactionID: transactionID},
	}
	for _, result := range results {
		if admitted, err := AdmitResultOutput(result.JSONValue()); err != nil || admitted.State != result.State {
			t.Fatalf("AdmitResultOutput(%s) result=%#v error=%v", result.State, admitted, err)
		}
	}
	mutant := results[1].JSONValue()
	mutant["appliedCount"] = 1
	if _, err := AdmitResultOutput(mutant); err == nil {
		t.Fatal("AdmitResultOutput() admitted applied work in an already-satisfied result")
	}
	for _, impossible := range []Result{
		{AppliedCountKnown: true, State: StateApplied, TransactionID: transactionID},
		{AppliedCountKnown: true, State: StateRolledBack, TransactionID: transactionID},
	} {
		if _, err := AdmitResultOutput(impossible.JSONValue()); err == nil {
			t.Fatalf("AdmitResultOutput() admitted unreachable result %#v", impossible)
		}
	}
}

func TestAdmitPlanOutputRejectsPortableAliasAsLexicalParent(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "nested/target.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	record := plan.JSONValue()
	record["createdDirectories"] = []any{"Nested"}
	if _, err := AdmitPlanOutput(record); err == nil || !strings.Contains(err.Error(), "portable identities") {
		t.Fatalf("AdmitPlanOutput() error=%v, want portable parent-alias rejection", err)
	}
}

func TestAdmitPlanOutputRejectsImpossibleCreatedDirectoryRelations(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "a/b/record.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}

	incomplete := clonePlan(plan)
	incomplete.CreatedDirectories = []string{"a"}
	refreshPlanIdentity(t, &incomplete)
	if _, err := AdmitPlanOutput(incomplete.JSONValue()); err == nil || !strings.Contains(err.Error(), "chain is incomplete") {
		t.Fatalf("AdmitPlanOutput(incomplete chain) error=%v", err)
	}

	contradictory := clonePlan(plan)
	contradictory.Operations[0].Before = Snapshot{ByteCount: 6, Exists: true, Mode: 0o644, SHA256: digest.SHA256BytesRef([]byte("before"))}
	contradictory.Operations[0].Action = ActionReplace
	refreshPlanIdentity(t, &contradictory)
	if _, err := AdmitPlanOutput(contradictory.JSONValue()); err == nil || !strings.Contains(err.Error(), "contradicts an existing target") {
		t.Fatalf("AdmitPlanOutput(contradictory before state) error=%v", err)
	}
}

func refreshPlanIdentity(t *testing.T, plan *Plan) {
	t.Helper()
	desiredStateID, err := digest.StableJSONSHA256Ref(desiredStateIdentityValue(*plan))
	if err != nil {
		t.Fatal(err)
	}
	plan.DesiredStateID = desiredStateID
	transactionID, err := digest.StableJSONSHA256Ref(planIdentityValue(*plan))
	if err != nil {
		t.Fatal(err)
	}
	plan.TransactionID = transactionID
}
