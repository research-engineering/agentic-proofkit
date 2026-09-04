package repositorytransaction

import (
	"context"
	"strings"
	"testing"
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
