package adoptionmaterialization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestMaterializationWholeChainIsCanonicalAndOwnerClosed(t *testing.T) {
	root := t.TempDir()
	request := validRequest(t, root)

	plan, err := BuildPlan(context.Background(), request, root)
	if err != nil {
		t.Fatalf("BuildPlan() error = %v", err)
	}
	planRaw := jsonRoundTripValue(t, plan.JSONValue())
	if admitted, err := AdmitPlanOutput(planRaw); err != nil || admitted.Transaction.TransactionID != plan.Transaction.TransactionID {
		t.Fatalf("AdmitPlanOutput() plan=%#v error=%v", admitted, err)
	}
	planBytes, err := stablejson.Marshal(plan.JSONValue())
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"Pilot materialization preserves admitted requirement meaning", "go test ./internal/pilot"} {
		if bytes.Contains(planBytes, []byte(forbidden)) {
			t.Fatalf("plan disclosed payload %q: %s", forbidden, planBytes)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".agentic-proofkit")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only plan created transaction state: %v", err)
	}

	receipt, exitCode, err := Apply(context.Background(), request, root, plan.Transaction.TransactionID, plan.Transaction.DesiredStateID)
	if err != nil || exitCode != 0 || receipt.State != ReceiptStatePassed || receipt.TransactionResult == nil || receipt.TransactionResult.State != repositorytransaction.StateApplied {
		t.Fatalf("Apply() receipt=%#v exit=%d err=%v", receipt, exitCode, err)
	}
	if admitted, err := AdmitReceiptOutput(jsonRoundTripValue(t, receipt.JSONValue())); err != nil || admitted.ReceiptID != receipt.ReceiptID {
		t.Fatalf("AdmitReceiptOutput() receipt=%#v error=%v", admitted, err)
	}

	sourceRaw := readJSON(t, filepath.Join(root, "docs/specs/pilot/requirements.v1.json"))
	source, err := requirementsourceadmission.Evaluate(sourceRaw)
	if err != nil || source.ExitCode != 0 {
		t.Fatalf("materialized source admission=%#v err=%v", source, err)
	}
	bindingRaw := readJSON(t, filepath.Join(root, "proofkit/requirement-bindings.json"))
	binding, err := requirementbinding.Build(bindingRaw)
	if err != nil || binding.Record.State != "passed" {
		t.Fatalf("materialized binding admission=%#v err=%v", binding, err)
	}
	inventoryRaw := readJSON(t, filepath.Join(root, "proofkit/test-evidence-inventory.json"))
	inventory, err := testevidenceinventory.EvaluateDirect(inventoryRaw)
	if err != nil || inventory.ExitCode != 0 {
		t.Fatalf("materialized inventory admission=%#v err=%v", inventory, err)
	}
	manifestRaw := readJSON(t, filepath.Join(root, ProjectManifestPath))
	manifest, err := AdmitManifest(manifestRaw)
	if err != nil || manifest.ProjectID != "pilot.project" || len(manifest.Routes) != 3 {
		t.Fatalf("materialized manifest=%#v err=%v", manifest, err)
	}
}

func TestMaterializationOutputAdmissionRejectsCrossOwnerMutants(t *testing.T) {
	root := t.TempDir()
	request := validRequest(t, root)
	plan, err := BuildPlan(context.Background(), request, root)
	if err != nil {
		t.Fatal(err)
	}
	planMutant := jsonRoundTripValue(t, plan.JSONValue()).(map[string]any)
	transaction := planMutant["transaction"].(map[string]any)
	operations := transaction["operations"].([]any)
	transaction["operations"] = operations[1:]
	if _, err := AdmitPlanOutput(planMutant); err == nil {
		t.Fatal("AdmitPlanOutput() admitted a transaction that omitted a manifest route")
	}

	requestRecord, err := admitRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	children, err := childArtifacts(requestRecord)
	if err != nil {
		t.Fatal(err)
	}
	forgedManifest := plan.Manifest
	forgedManifest.Routes = append([]Route(nil), plan.Manifest.Routes...)
	forgedManifest.Routes[0].ArtifactID = digest.SHA256BytesRef([]byte("forged artifact identity"))
	forgedManifest.ManifestID, err = digest.StableJSONSHA256Ref(forgedManifest.identityValue())
	if err != nil {
		t.Fatal(err)
	}
	manifestContent, err := stablejson.Marshal(forgedManifest.JSONValue())
	if err != nil {
		t.Fatal(err)
	}
	artifacts := append(append([]artifact(nil), children...), artifact{
		Content: manifestContent, ID: forgedManifest.ManifestID, Kind: ArtifactProjectManifest, Path: ProjectManifestPath,
	})
	targets := make([]repositorytransaction.Target, 0, len(artifacts))
	for _, item := range artifacts {
		targets = append(targets, repositorytransaction.Target{Content: item.Content, Mode: 0o644, Path: item.Path})
	}
	forgedTransaction, err := repositorytransaction.BuildPlan(context.Background(), root, targets)
	if err != nil {
		t.Fatal(err)
	}
	forgedPlan := plan
	forgedPlan.Manifest = forgedManifest
	forgedPlan.Transaction = forgedTransaction
	if _, err := AdmitPlanOutput(forgedPlan.JSONValue()); err == nil {
		t.Fatal("AdmitPlanOutput() admitted a route identity that did not match its target bytes")
	}

	receipt, exitCode, err := Apply(context.Background(), request, root, plan.Transaction.TransactionID, plan.Transaction.DesiredStateID)
	if err != nil || exitCode != 0 {
		t.Fatalf("Apply() receipt=%#v exit=%d error=%v", receipt, exitCode, err)
	}
	receiptMutant := jsonRoundTripValue(t, receipt.JSONValue()).(map[string]any)
	receiptMutant["state"] = ReceiptStateBlocked
	identity := cloneValue(t, receiptMutant).(map[string]any)
	delete(identity, "receiptId")
	receiptMutant["receiptId"], err = digest.StableJSONSHA256Ref(identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitReceiptOutput(receiptMutant); err == nil {
		t.Fatal("AdmitReceiptOutput() admitted a state that contradicted its transaction result")
	}
}

func TestReceiptAdmissionRejectsOperationAttributionMutants(t *testing.T) {
	transactionID := "sha256:" + strings.Repeat("a", 64)
	desiredStateID := "sha256:" + strings.Repeat("b", 64)
	tests := []Receipt{
		{
			ExpectedDesiredStateID: desiredStateID,
			ExpectedTransactionID:  transactionID,
			NonClaims:              mergedNonClaims(nil),
			Operation:              OperationApply,
			State:                  ReceiptStatePassed,
			TransactionResult: &repositorytransaction.Result{
				AppliedCount: 1, AppliedCountKnown: true, RecoveredBy: repositorytransaction.RecoveryResume,
				State: repositorytransaction.StateApplied, TransactionID: transactionID,
			},
		},
		{
			ExpectedTransactionID: transactionID,
			NonClaims:             mergedNonClaims(nil),
			Operation:             OperationRecover,
			State:                 ReceiptStatePassed,
			TransactionResult: &repositorytransaction.Result{
				AppliedCount: 1, AppliedCountKnown: true, State: repositorytransaction.StateApplied, TransactionID: transactionID,
			},
		},
		{
			ExpectedTransactionID: transactionID,
			FailureClass:          "cleanup_failed",
			NonClaims:             mergedNonClaims(nil),
			Operation:             OperationRecover,
			State:                 ReceiptStateCleanupRequired,
			TransactionResult: &repositorytransaction.Result{
				FailureClass: "cleanup_failed", State: repositorytransaction.StateCleanupRequired, TransactionID: transactionID,
			},
		},
		{
			ExpectedTransactionID: transactionID,
			FailureClass:          "ambiguous_target_state",
			NonClaims:             mergedNonClaims(nil),
			Operation:             OperationRecover,
			State:                 ReceiptStateRecoveryRequired,
			TransactionResult: &repositorytransaction.Result{
				FailureClass: "ambiguous_target_state", State: repositorytransaction.StateRecoveryRequired,
				TransactionID: "sha256:" + strings.Repeat("c", 64),
			},
		},
		{
			ExpectedTransactionID: transactionID,
			FailureClass:          "ambiguous_target_state",
			NonClaims:             mergedNonClaims(nil),
			Operation:             OperationRecover,
			State:                 ReceiptStateRecoveryRequired,
			TransactionResult: &repositorytransaction.Result{
				AppliedCount: 1, AppliedCountKnown: true, FailureClass: "ambiguous_target_state",
				State: repositorytransaction.StateRecoveryRequired,
			},
		},
	}
	for index := range tests {
		identity := tests[index].identityValue()
		receiptID, err := digest.StableJSONSHA256Ref(identity)
		if err != nil {
			t.Fatal(err)
		}
		tests[index].ReceiptID = receiptID
		if _, err := AdmitReceiptOutput(jsonRoundTripValue(t, tests[index].JSONValue())); err == nil {
			t.Fatalf("AdmitReceiptOutput() admitted operation-attribution mutant %d", index)
		}
	}
}

func TestRecoveryWithUnknownJournalIdentityCannotPass(t *testing.T) {
	root := t.TempDir()
	active := filepath.Join(root, ".agentic-proofkit", "transactions", "active")
	if err := os.MkdirAll(active, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{filepath.Join(root, ".agentic-proofkit"), filepath.Join(root, ".agentic-proofkit", "transactions"), active} {
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(active, "journal.tmp"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	transactionID := "sha256:" + strings.Repeat("c", 64)
	receipt, exitCode, err := Recover(context.Background(), root, transactionID, repositorytransaction.RecoveryRollback)
	if err != nil || exitCode != 1 || receipt.State != ReceiptStateRecoveryRequired || receipt.TransactionResult == nil || receipt.TransactionResult.TransactionID != "" {
		t.Fatalf("Recover() receipt=%#v exit=%d error=%v", receipt, exitCode, err)
	}
	if _, err := AdmitReceiptOutput(jsonRoundTripValue(t, receipt.JSONValue())); err != nil {
		t.Fatalf("AdmitReceiptOutput() rejected the fail-closed recovery receipt: %v", err)
	}
}

func jsonRoundTripValue(t *testing.T, value any) any {
	t.Helper()
	content, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestApplyBlocksStaleMutationButAcceptsLostAcknowledgementRetry(t *testing.T) {
	root := t.TempDir()
	request := validRequest(t, root)
	initial, err := BuildPlan(context.Background(), request, root)
	if err != nil {
		t.Fatal(err)
	}

	changed := cloneRequest(t, request)
	source := changed["requirementSources"].([]any)[0].(map[string]any)
	requirement := source["requirements"].([]any)[0].(map[string]any)
	requirement["invariant"] = "Pilot materialization preserves revised admitted requirement meaning."
	blocked, exitCode, err := Apply(context.Background(), changed, root, initial.Transaction.TransactionID, initial.Transaction.DesiredStateID)
	if err != nil || exitCode != 1 || blocked.State != ReceiptStateBlocked || blocked.FailureClass != "desired_state_identity_mismatch" || blocked.TransactionResult != nil {
		t.Fatalf("stale Apply() receipt=%#v exit=%d err=%v", blocked, exitCode, err)
	}
	if _, err := os.Stat(filepath.Join(root, "docs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale apply mutated repository: %v", err)
	}

	first, exitCode, err := Apply(context.Background(), request, root, initial.Transaction.TransactionID, initial.Transaction.DesiredStateID)
	if err != nil || exitCode != 0 || first.State != ReceiptStatePassed {
		t.Fatalf("first Apply() receipt=%#v exit=%d err=%v", first, exitCode, err)
	}
	retry, exitCode, err := Apply(context.Background(), request, root, initial.Transaction.TransactionID, initial.Transaction.DesiredStateID)
	if err != nil || exitCode != 0 || retry.State != ReceiptStatePassed || retry.TransactionResult == nil || retry.TransactionResult.State != repositorytransaction.StateAlreadySatisfied {
		t.Fatalf("retry Apply() receipt=%#v exit=%d err=%v", retry, exitCode, err)
	}
	if retry.ExpectedTransactionID != initial.Transaction.TransactionID || retry.ExpectedDesiredStateID != initial.Transaction.DesiredStateID || retry.TransactionResult.TransactionID != initial.Transaction.TransactionID {
		t.Fatalf("retry was not bound to the retained terminal transaction: %#v", retry)
	}
	wrongTransaction := "sha256:" + strings.Repeat("1", 64)
	blocked, exitCode, err = Apply(context.Background(), request, root, wrongTransaction, initial.Transaction.DesiredStateID)
	if err != nil || exitCode != 1 || blocked.FailureClass != "transaction_identity_mismatch" {
		t.Fatalf("wrong-transaction retry receipt=%#v exit=%d err=%v", blocked, exitCode, err)
	}
	wrongDesired := "sha256:" + strings.Repeat("0", 64)
	blocked, exitCode, err = Apply(context.Background(), request, root, initial.Transaction.TransactionID, wrongDesired)
	if err != nil || exitCode != 1 || blocked.FailureClass != "desired_state_identity_mismatch" {
		t.Fatalf("wrong desired-state Apply() receipt=%#v exit=%d err=%v", blocked, exitCode, err)
	}
}

func TestTerminalReplayClassificationPreservesDistinctOutcomes(t *testing.T) {
	transactionID := "sha256:" + strings.Repeat("a", 64)
	operational := errors.New("native observation failed")
	tests := []struct {
		name             string
		result           repositorytransaction.Result
		err              error
		wantFailureClass string
		wantError        error
		wantState        string
	}{
		{name: "admitted replay", result: repositorytransaction.Result{AppliedCountKnown: true, State: repositorytransaction.StateAlreadySatisfied, TransactionID: transactionID}, wantState: repositorytransaction.StateAlreadySatisfied},
		{name: "historical result only", result: repositorytransaction.Result{AppliedCount: 3, AppliedCountKnown: true, RecoveredBy: repositorytransaction.RecoveryResume, State: repositorytransaction.StateApplied, TransactionID: transactionID}, wantFailureClass: "transaction_identity_mismatch"},
		{name: "read cleanup", err: repositorytransaction.ErrReadCleanup, wantError: repositorytransaction.ErrReadCleanup},
		{name: "busy", err: repositorytransaction.ErrBusy, wantFailureClass: "transaction_busy"},
		{name: "cancelled", err: context.Canceled, wantError: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded, wantError: context.DeadlineExceeded},
		{name: "absent", err: repositorytransaction.ErrReplayMismatch, wantFailureClass: "transaction_identity_mismatch"},
		{name: "operational", err: operational, wantError: operational},
		{name: "mismatch and cleanup", err: errors.Join(repositorytransaction.ErrReplayMismatch, repositorytransaction.ErrReadCleanup), wantError: repositorytransaction.ErrReadCleanup},
		{name: "busy and cleanup", err: errors.Join(repositorytransaction.ErrBusy, repositorytransaction.ErrReadCleanup), wantError: repositorytransaction.ErrReadCleanup},
		{name: "pending and cleanup", err: errors.Join(repositorytransaction.ErrRecoveryRequired, repositorytransaction.ErrReadCleanup), wantError: repositorytransaction.ErrReadCleanup},
		{name: "wrong terminal state", result: repositorytransaction.Result{AppliedCountKnown: true, State: repositorytransaction.StateRolledBack, TransactionID: transactionID}, wantFailureClass: "transaction_identity_mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, failureClass, err := classifyTerminalReplay(test.result, test.err)
			if !errors.Is(err, test.wantError) || failureClass != test.wantFailureClass || result.State != test.wantState {
				t.Fatalf("classifyTerminalReplay() result=%#v failure=%q error=%v", result, failureClass, err)
			}
			if test.wantState == repositorytransaction.StateAlreadySatisfied && (result.AppliedCount != 0 || !result.AppliedCountKnown || result.RecoveredBy != "" || result.TransactionID != transactionID) {
				t.Fatalf("lost-ack replay result=%#v", result)
			}
		})
	}
}

func TestApplyDistinguishesStaleBeforeSnapshotFromDesiredState(t *testing.T) {
	root := t.TempDir()
	request := validRequest(t, root)
	initial, err := BuildPlan(context.Background(), request, root)
	if err != nil {
		t.Fatal(err)
	}
	existing := cloneRequest(t, request)["requirementSources"].([]any)[0].(map[string]any)
	existing["requirements"].([]any)[0].(map[string]any)["invariant"] = "A different but owner-valid current invariant."
	content, err := stablejson.Marshal(existing)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, root, "docs/specs/pilot/requirements.v1.json", content)
	receipt, exitCode, err := Apply(context.Background(), request, root, initial.Transaction.TransactionID, initial.Transaction.DesiredStateID)
	if err != nil || exitCode != 1 || receipt.State != ReceiptStateBlocked || receipt.FailureClass != "transaction_identity_mismatch" {
		t.Fatalf("stale-before Apply() receipt=%#v exit=%d err=%v", receipt, exitCode, err)
	}
}

func TestApplyReportsObservedPendingTransaction(t *testing.T) {
	root := t.TempDir()
	request := validRequest(t, root)
	initial, err := BuildPlan(context.Background(), request, root)
	if err != nil {
		t.Fatal(err)
	}
	observedID := "sha256:" + strings.Repeat("a", 64)
	tombstone := filepath.Join(root, ".agentic-proofkit", "transactions", "gc-"+strings.TrimPrefix(observedID, "sha256:")+"-applied")
	if err := os.MkdirAll(tombstone, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(root, ".agentic-proofkit"), filepath.Join(root, ".agentic-proofkit", "transactions"), tombstone} {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tombstone, "ready"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	receipt, exitCode, err := Apply(context.Background(), request, root, initial.Transaction.TransactionID, initial.Transaction.DesiredStateID)
	if err != nil || exitCode != 1 || receipt.State != ReceiptStateRecoveryRequired || receipt.TransactionResult == nil || receipt.TransactionResult.TransactionID != observedID {
		t.Fatalf("pending Apply() receipt=%#v exit=%d err=%v", receipt, exitCode, err)
	}
}

func TestMaterializationReplacesOnlyCompatibleOwnerRecords(t *testing.T) {
	root := t.TempDir()
	request := validRequest(t, root)
	initial, err := BuildPlan(context.Background(), request, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, exitCode, err := Apply(context.Background(), request, root, initial.Transaction.TransactionID, initial.Transaction.DesiredStateID); err != nil || exitCode != 0 {
		t.Fatalf("initial Apply() exit=%d err=%v", exitCode, err)
	}

	changed := cloneRequest(t, request)
	requirement := changed["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)[0].(map[string]any)
	requirement["invariant"] = "Pilot materialization preserves a reviewed replacement invariant."
	replacement, err := BuildPlan(context.Background(), changed, root)
	if err != nil {
		t.Fatalf("replacement BuildPlan() error = %v", err)
	}
	if _, exitCode, err := Apply(context.Background(), changed, root, replacement.Transaction.TransactionID, replacement.Transaction.DesiredStateID); err != nil || exitCode != 0 {
		t.Fatalf("replacement Apply() exit=%d err=%v", exitCode, err)
	}
	got := readJSON(t, filepath.Join(root, "docs/specs/pilot/requirements.v1.json")).(map[string]any)
	gotInvariant := got["requirements"].([]any)[0].(map[string]any)["invariant"]
	if gotInvariant != requirement["invariant"] {
		t.Fatalf("materialized invariant=%q, want %q", gotInvariant, requirement["invariant"])
	}

	unknownRoot := t.TempDir()
	unknown := validRequest(t, unknownRoot)
	mustWrite(t, unknownRoot, "proofkit/requirement-bindings.json", []byte("{}\n"))
	if _, err := BuildPlan(context.Background(), unknown, unknownRoot); err == nil || !strings.Contains(err.Error(), "incompatible ownership") {
		t.Fatalf("BuildPlan(unknown owner) error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(unknownRoot, ".agentic-proofkit")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owner rejection created transaction state: %v", err)
	}
}

func TestMaterializationRejectsCrossRecordDriftAndManifestMutation(t *testing.T) {
	root := t.TempDir()
	request := validRequest(t, root)
	drifted := cloneRequest(t, request)
	binding := drifted["requirementProofBinding"].(map[string]any)["record"].(map[string]any)
	binding["requirements"].([]any)[0].(map[string]any)["ownerId"] = "pilot.other"
	if _, err := BuildPlan(context.Background(), drifted, root); err == nil || !strings.Contains(err.Error(), "projection does not match") {
		t.Fatalf("BuildPlan(drifted owner) error=%v", err)
	}

	plan, err := BuildPlan(context.Background(), request, root)
	if err != nil {
		t.Fatal(err)
	}
	manifest := cloneValue(t, plan.Manifest.JSONValue()).(map[string]any)
	manifest["routes"].([]any)[0].(map[string]any)["path"] = "../outside.json"
	if _, err := AdmitManifest(manifest); err == nil {
		t.Fatal("AdmitManifest() accepted root-escaping route")
	}

}

func TestMaterializationIdentifiersAreScopedByChildOwner(t *testing.T) {
	root := t.TempDir()
	request := validRequest(t, root)
	request["requirementSources"].([]any)[0].(map[string]any)["sourceId"] = "pilot.bindings"
	if _, err := BuildPlan(context.Background(), request, root); err != nil {
		t.Fatalf("BuildPlan(cross-owner identifier reuse) error=%v", err)
	}
}

func TestReceiptOutcomeIsOperationSpecific(t *testing.T) {
	tests := []struct {
		operation string
		state     string
		want      string
		exitCode  int
	}{
		{OperationApply, repositorytransaction.StateApplied, ReceiptStatePassed, 0},
		{OperationApply, repositorytransaction.StateAlreadySatisfied, ReceiptStatePassed, 0},
		{OperationApply, repositorytransaction.StateRolledBack, ReceiptStateFailed, 1},
		{OperationRecover, repositorytransaction.StateApplied, ReceiptStatePassed, 0},
		{OperationRecover, repositorytransaction.StateRolledBack, ReceiptStatePassed, 0},
		{OperationRecover, repositorytransaction.StateRecoveryRequired, ReceiptStateRecoveryRequired, 1},
		{OperationRecover, repositorytransaction.StateCleanupRequired, ReceiptStateCleanupRequired, 1},
		{OperationRecover, repositorytransaction.StateDurabilityUnknown, ReceiptStateDurabilityUnknown, 1},
	}
	for _, test := range tests {
		got, exitCode := receiptOutcome(test.operation, repositorytransaction.Result{State: test.state})
		if got != test.want || exitCode != test.exitCode {
			t.Fatalf("receiptOutcome(%s, %s)=(%s,%d), want (%s,%d)", test.operation, test.state, got, exitCode, test.want, test.exitCode)
		}
	}
}

func validRequest(t *testing.T, root string) map[string]any {
	t.Helper()
	mustWrite(t, root, "README.md", []byte("# Pilot\n"))
	inventory, err := repositoryinventory.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	sourcePlan, err := adoptionplan.Build(adoptionplan.IntentFresh, inventory, "")
	if err != nil {
		t.Fatal(err)
	}
	requirementNonClaims := []any{"Pilot requirement fixture does not prove rollout."}
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"requestKind":   RequestKind,
		"requestId":     "pilot.materialization.request",
		"projectId":     "pilot.project",
		"sourcePlan":    sourcePlan.JSONValue(),
		"requirementSources": []any{map[string]any{
			"schemaVersion":    json.Number("1"),
			"sourceId":         "pilot.requirements",
			"specPackagePath":  "docs/specs/pilot",
			"overviewPath":     "docs/specs/pilot/overview.md",
			"requirementsPath": "docs/specs/pilot/requirements.v1.json",
			"nonClaims":        []any{"Pilot source fixture does not prove production readiness."},
			"requirements": []any{map[string]any{
				"claimLevel": "blocking",
				"deferral":   nil,
				"invariant":  "Pilot materialization preserves admitted requirement meaning.",
				"lifecycle": map[string]any{
					"evidenceRefs":              []any{},
					"replacementRequirementIds": []any{},
					"state":                     "active",
				},
				"nonClaimRefs":     []any{},
				"nonClaims":        requirementNonClaims,
				"ownerId":          "pilot.owner",
				"proofBindingRefs": []any{"proofkit/requirement-bindings.json"},
				"requirementId":    "REQ-PILOT-001",
				"riskClass":        "high",
				"updatePolicy": map[string]any{
					"requiresImpactDeclaration":  true,
					"requiresProofBindingReview": true,
					"reviewOwnerId":              "pilot.owner",
				},
			}},
		}},
		"requirementProofBinding": map[string]any{
			"path": "proofkit/requirement-bindings.json",
			"record": map[string]any{
				"schemaVersion": json.Number("1"),
				"bindingId":     "pilot.bindings",
				"requirements": []any{map[string]any{
					"claimLevel":    "blocking",
					"nonClaims":     requirementNonClaims,
					"ownerId":       "pilot.owner",
					"proofState":    "witness_backed",
					"requirementId": "REQ-PILOT-001",
					"specPath":      "docs/specs/pilot/requirements.v1.json",
				}},
				"bindings": []any{map[string]any{
					"commandIds":         []any{"pilot.command.test"},
					"environmentClasses": []any{"local-go"},
					"requirementId":      "REQ-PILOT-001",
					"scenarioId":         "pilot.scenario.materialization",
					"witnessId":          "pilot.witness.materialization",
					"witnessKind":        "contract",
					"witnessPath":        "internal/pilot/materialization_test.go",
				}},
				"witnessCommands": []any{map[string]any{
					"command":            "go test ./internal/pilot",
					"commandId":          "pilot.command.test",
					"environmentClasses": []any{"local-go"},
				}},
				"selection": map[string]any{
					"changedPaths":   []any{},
					"ownerIds":       []any{},
					"requirementIds": []any{},
				},
				"nonClaims": []any{"Pilot binding fixture does not execute witnesses."},
			},
		},
		"testEvidenceInventory": map[string]any{
			"path": "proofkit/test-evidence-inventory.json",
			"record": map[string]any{
				"schemaVersion": json.Number("1"),
				"inventoryId":   "pilot.inventory",
				"authority":     "caller_owned_inventory",
				"entries": []any{map[string]any{
					"testId":             "pilot.test.materialization",
					"selector":           "go test ./internal/pilot -run TestMaterialization",
					"sourcePath":         "internal/pilot/materialization_test.go",
					"ownerId":            "pilot.owner",
					"evidenceClass":      "declared_semantic_falsifier_route",
					"requirementRefs":    []any{"REQ-PILOT-001"},
					"ownerInvariantRefs": []any{},
					"commandRefs":        []any{"pilot.command.test"},
					"witnessRefs":        []any{"pilot.witness.materialization"},
					"falsifier": map[string]any{
						"falsifierId":                "pilot.falsifier.materialization",
						"negativeCaseId":             "pilot.case.materialization",
						"wrongImplementationClassId": "pilot.wrong.materialization",
						"dominanceGroup":             "pilot.materialization",
						"supersedes":                 []any{},
					},
					"oracle": map[string]any{
						"oracleId":              "pilot.oracle.materialization",
						"oracleKind":            "negative_exit_and_diagnostic",
						"expectedPublicOutcome": "invalid materialization fails closed",
						"assertionSummary":      "A contradictory materialization request is rejected before mutation.",
					},
					"nonClaims": []any{},
				}},
				"nonClaims": []any{"Pilot inventory fixture does not execute native tests."},
			},
		},
		"nonClaims": []any{"Pilot materialization request is test-only."},
	}
}

func cloneRequest(t *testing.T, request map[string]any) map[string]any {
	t.Helper()
	return cloneValue(t, request).(map[string]any)
}

func cloneValue(t *testing.T, value any) any {
	t.Helper()
	content, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	clone, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	return clone
}

func readJSON(t *testing.T, path string) any {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	value, err := admission.DecodeJSON(file, repositorytransaction.MaximumFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustWrite(t *testing.T, root, relative string, content []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}
