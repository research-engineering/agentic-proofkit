package projectstatus

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestEvaluateTotalStateActionTable(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.060322937390720972859694282639537757818712419857577877895991208334865304069513")
	tests := []struct {
		name       string
		snapshot   inspectionSnapshot
		wantState  ProjectState
		wantAction string
		wantIssues []string
	}{
		{name: "invalid transaction", snapshot: transactionSnapshot(TransactionInvalid, ""), wantState: StateBlocked, wantAction: ActionRepairControlState, wantIssues: []string{IssueTransactionInvalid}},
		{name: "recoverable transaction", snapshot: transactionSnapshot(TransactionRecoverable, digest.SHA256TextRef("transaction")), wantState: StateRecoveryRequired, wantAction: ActionChooseRecovery, wantIssues: []string{IssueTransactionRecoveryRequired}},
		{name: "missing manifest", snapshot: transactionSnapshot(TransactionClean, ""), wantState: StateUninitialized, wantAction: ActionChooseAdoptionMode, wantIssues: []string{IssueManifestMissing}},
		{name: "invalid manifest", snapshot: invalidManifestSnapshot(), wantState: StateBlocked, wantAction: ActionRepairProjectRecords, wantIssues: []string{IssueManifestInvalid}},
		{name: "missing child", snapshot: childStateSnapshot(ChildMissing), wantState: StateStale, wantAction: ActionRematerializeProject, wantIssues: []string{IssueChildMissing}},
		{name: "mismatched child", snapshot: childStateSnapshot(ChildDigestMismatch), wantState: StateStale, wantAction: ActionRematerializeProject, wantIssues: []string{IssueChildDigestMismatch}},
		{name: "invalid child dominates missing", snapshot: mixedInvalidSnapshot(), wantState: StateBlocked, wantAction: ActionRepairProjectRecords, wantIssues: []string{IssueChildInvalid, IssueChildMissing}},
		{name: "invalid closure", snapshot: closureSnapshot(ClosureInvalid), wantState: StateBlocked, wantAction: ActionRepairProjectRecords, wantIssues: []string{IssueClosureInvalid}},
		{name: "admitted project", snapshot: closureSnapshot(ClosureAdmitted), wantState: StateVerificationRequired, wantAction: ActionRunRepositoryVerification, wantIssues: []string{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, err := evaluate(test.snapshot)
			if err != nil {
				t.Fatalf("evaluate() error = %v", err)
			}
			if status.ProjectState != test.wantState || status.NextAction.ActionClass != test.wantAction || !reflect.DeepEqual(status.IssueCodes, test.wantIssues) {
				t.Fatalf("evaluate() = state %q action %q issues %v", status.ProjectState, status.NextAction.ActionClass, status.IssueCodes)
			}
			if status.NextAction.Executable {
				t.Fatal("evaluate() emitted executable next action")
			}
			next, err := NextFromStatus(status)
			if err != nil {
				t.Fatalf("NextFromStatus() error = %v", err)
			}
			if next.StatusRef != status.StatusID || !reflect.DeepEqual(next.Action, status.NextAction) {
				t.Fatal("NextFromStatus() lost the status-owned action")
			}
		})
	}
}

func TestSnapshotIdentityBindsEveryDecisionOperand(t *testing.T) {
	base := closureSnapshot(ClosureAdmitted)
	baseID, err := snapshotID(base)
	if err != nil {
		t.Fatal(err)
	}
	variants := map[string]inspectionSnapshot{
		"transaction epoch": func() inspectionSnapshot {
			value := base
			value.Transaction.Epoch = digest.SHA256TextRef("other epoch")
			return value
		}(),
		"transaction state": func() inspectionSnapshot {
			value := base
			value.Transaction.State = TransactionInvalid
			return value
		}(),
		"transaction identity": func() inspectionSnapshot {
			value := base
			value.Transaction.TransactionID = digest.SHA256TextRef("transaction")
			return value
		}(),
		"manifest digest": func() inspectionSnapshot {
			value := base
			value.Manifest.ContentDigest = digest.SHA256TextRef("other manifest")
			return value
		}(),
		"manifest identity": func() inspectionSnapshot {
			value := base
			value.Manifest.ManifestID = digest.SHA256TextRef("other manifest identity")
			return value
		}(),
		"manifest state": func() inspectionSnapshot {
			value := base
			value.Manifest.State = ManifestInvalid
			return value
		}(),
		"project id": func() inspectionSnapshot { value := base; value.ProjectID = "project.other"; return value }(),
		"child kind": func() inspectionSnapshot {
			value := base
			value.Children = cloneChildren(base.Children)
			value.Children[0].ArtifactKind = "other_source"
			return value
		}(),
		"child expected digest": func() inspectionSnapshot {
			value := base
			value.Children = cloneChildren(base.Children)
			value.Children[0].ExpectedDigest = digest.SHA256TextRef("other child")
			value.Children[0].ObservedDigest = value.Children[0].ExpectedDigest
			return value
		}(),
		"child observed digest": func() inspectionSnapshot {
			value := base
			value.Children = cloneChildren(base.Children)
			value.Children[0].ObservedDigest = digest.SHA256TextRef("other observed child")
			return value
		}(),
		"child state": func() inspectionSnapshot {
			value := base
			value.Children = cloneChildren(base.Children)
			value.Children[0].State = ChildMissing
			return value
		}(),
		"child cardinality": func() inspectionSnapshot {
			value := base
			value.Children = cloneChildren(base.Children[1:])
			return value
		}(),
		"child order": func() inspectionSnapshot {
			value := base
			value.Children = cloneChildren(base.Children)
			value.Children[0], value.Children[1] = value.Children[1], value.Children[0]
			return value
		}(),
		"closure": closureSnapshot(ClosureInvalid),
	}
	for name, variant := range variants {
		t.Run(name, func(t *testing.T) {
			variantID, err := snapshotID(variant)
			if err != nil {
				t.Fatal(err)
			}
			if variantID == baseID {
				t.Fatal("decision operand did not change snapshot identity")
			}
		})
	}
}

func TestOutputAdmissionRejectsReidentifiedStateActionMismatch(t *testing.T) {
	status, err := evaluate(closureSnapshot(ClosureAdmitted))
	if err != nil {
		t.Fatal(err)
	}
	status.NextAction.ActionClass = ActionRepairProjectRecords
	status.NextAction.ActionID = "proofkit.project-status.action." + status.NextAction.ActionClass
	status.NextAction.ContextRef = ""
	status.StatusID, err = digest.StableJSONSHA256Ref(status.identityValue())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitStatusOutput(status.JSONValue()); err == nil {
		t.Fatalf("AdmitStatusOutput() error = %v", err)
	}
}

func TestOutputAdmissionRejectsUnreachableClosureCombination(t *testing.T) {
	status, err := evaluate(closureSnapshot(ClosureInvalid))
	if err != nil {
		t.Fatal(err)
	}
	status.IssueCodes = []string{IssueClosureInvalid, IssueChildMissing}
	status.StatusID, err = digest.StableJSONSHA256Ref(status.identityValue())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitStatusOutput(status.JSONValue()); err == nil {
		t.Fatal("AdmitStatusOutput() admitted closure evaluation before child admission")
	}
}

func TestSnapshotValidationRejectsPrematureClosureAndDigestDrift(t *testing.T) {
	premature := childStateSnapshot(ChildMissing)
	premature.ClosureState = ClosureAdmitted
	if _, err := evaluate(premature); err == nil || !strings.Contains(err.Error(), "before child admission") {
		t.Fatalf("evaluate() error = %v", err)
	}
	drifted := closureSnapshot(ClosureAdmitted)
	drifted.Children[0].ObservedDigest = digest.SHA256TextRef("drifted")
	if _, err := evaluate(drifted); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("evaluate() error = %v", err)
	}
}

func TestTextProjectionIsBoundedAndSemanticallyDerived(t *testing.T) {
	for _, snapshot := range []inspectionSnapshot{
		transactionSnapshot(TransactionInvalid, ""),
		transactionSnapshot(TransactionRecoverable, digest.SHA256TextRef("transaction")),
		transactionSnapshot(TransactionClean, ""),
		invalidManifestSnapshot(),
		childStateSnapshot(ChildMissing),
		closureSnapshot(ClosureAdmitted),
	} {
		status, err := evaluate(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		statusLines, err := StatusText(status)
		if err != nil {
			t.Fatal(err)
		}
		wantStatusLines := []TextLine{
			{Label: "Project status"},
			{Label: "State", Value: string(status.ProjectState)},
			{Label: "snapshot", Value: status.SnapshotID},
			{Label: "Next", Value: status.NextAction.ActionClass},
		}
		if len(status.IssueCodes) > 0 {
			wantStatusLines = append(wantStatusLines, TextLine{Label: "Issues", Value: strings.Join(status.IssueCodes, ", ")})
		}
		if !reflect.DeepEqual(statusLines, wantStatusLines) {
			t.Fatalf("StatusText() = %#v, want %#v", statusLines, wantStatusLines)
		}
		statusText, err := RenderText(statusLines)
		if err != nil {
			t.Fatal(err)
		}
		if len(statusText) > MaximumTextBytes || strings.Count(statusText, "\n") > MaximumTextLines || !strings.Contains(statusText, string(status.ProjectState)) {
			t.Fatalf("RenderText(status) = %q", statusText)
		}

		next, err := NextFromStatus(status)
		if err != nil {
			t.Fatal(err)
		}
		nextLines, err := NextText(next)
		if err != nil {
			t.Fatal(err)
		}
		wantNextLines := []TextLine{
			{Label: "Project next action"},
			{Label: "State", Value: string(next.ProjectState)},
			{Label: "Action", Value: next.Action.ActionClass},
			{Label: "Executable", Value: "false"},
		}
		if len(next.Action.CommandRoute) > 0 {
			wantNextLines = append(wantNextLines, TextLine{Label: "Route", Value: strings.Join(next.Action.CommandRoute, " ")})
		}
		if next.Action.ContextRef != "" {
			wantNextLines = append(wantNextLines, TextLine{Label: "Context", Value: next.Action.ContextRef})
		}
		if next.Action.RequiredDecision != "" {
			wantNextLines = append(wantNextLines, TextLine{Label: "Decision", Value: next.Action.RequiredDecision})
		}
		if len(next.IssueCodes) > 0 {
			wantNextLines = append(wantNextLines, TextLine{Label: "Issues", Value: strings.Join(next.IssueCodes, ", ")})
		}
		if !reflect.DeepEqual(nextLines, wantNextLines) {
			t.Fatalf("NextText() = %#v, want %#v", nextLines, wantNextLines)
		}
		nextText, err := RenderText(nextLines)
		if err != nil {
			t.Fatal(err)
		}
		if len(nextText) > MaximumTextBytes || strings.Count(nextText, "\n") > MaximumTextLines || !strings.Contains(nextText, next.Action.ActionClass) || !strings.Contains(nextText, next.Action.ContextRef) {
			t.Fatalf("RenderText(next) = %q", nextText)
		}
	}
}

func TestNextTextEquivalenceIntentionallyExcludesJSONIdentity(t *testing.T) {
	firstSnapshot := transactionSnapshot(TransactionClean, "")
	secondSnapshot := transactionSnapshot(TransactionClean, "")
	secondSnapshot.Transaction.Epoch = digest.SHA256TextRef("different clean control epoch")
	firstStatus, err := evaluate(firstSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	secondStatus, err := evaluate(secondSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	firstNext, err := NextFromStatus(firstStatus)
	if err != nil {
		t.Fatal(err)
	}
	secondNext, err := NextFromStatus(secondStatus)
	if err != nil {
		t.Fatal(err)
	}
	if firstNext.PacketID == secondNext.PacketID || firstNext.SnapshotID == secondNext.SnapshotID || firstNext.StatusRef == secondNext.StatusRef {
		t.Fatal("distinct snapshots did not produce distinct JSON identity coordinates")
	}
	firstLines, err := NextText(firstNext)
	if err != nil {
		t.Fatal(err)
	}
	secondLines, err := NextText(secondNext)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstLines, secondLines) {
		t.Fatalf("JSON-only identity changed text projection: first=%#v second=%#v", firstLines, secondLines)
	}
}

func transactionSnapshot(state TransactionState, transactionID string) inspectionSnapshot {
	return inspectionSnapshot{
		ClosureState: ClosureNotEvaluated,
		Manifest:     manifestObservation{State: ManifestAbsent},
		Transaction: transactionObservation{
			Epoch: digest.SHA256TextRef("control epoch"), State: state, TransactionID: transactionID,
		},
	}
}

func invalidManifestSnapshot() inspectionSnapshot {
	snapshot := transactionSnapshot(TransactionClean, "")
	snapshot.Manifest = manifestObservation{State: ManifestInvalid, ContentDigest: digest.SHA256TextRef("invalid manifest")}
	return snapshot
}

func closureSnapshot(state ClosureState) inspectionSnapshot {
	manifestDigest := digest.SHA256TextRef("manifest")
	return inspectionSnapshot{
		Children: []childObservation{
			admittedChild("requirement_source", "source"),
			admittedChild("requirement_proof_binding", "binding"),
			admittedChild("test_evidence_inventory", "inventory"),
		},
		ClosureState: state,
		Manifest: manifestObservation{
			ContentDigest: manifestDigest, ManifestID: digest.SHA256TextRef("manifest identity"), State: ManifestAdmitted,
		},
		ProjectID:   "project.test",
		Transaction: transactionObservation{Epoch: digest.SHA256TextRef("control epoch"), State: TransactionClean},
	}
}

func childStateSnapshot(state ChildState) inspectionSnapshot {
	snapshot := closureSnapshot(ClosureAdmitted)
	snapshot.ClosureState = ClosureNotEvaluated
	snapshot.Children = cloneChildren(snapshot.Children)
	child := &snapshot.Children[0]
	child.State = state
	switch state {
	case ChildMissing:
		child.ObservedDigest = ""
	case ChildDigestMismatch:
		child.ObservedDigest = digest.SHA256TextRef("changed source")
	case ChildInvalid:
		child.ObservedDigest = child.ExpectedDigest
	}
	return snapshot
}

func mixedInvalidSnapshot() inspectionSnapshot {
	snapshot := childStateSnapshot(ChildInvalid)
	snapshot.Children[1].State = ChildMissing
	snapshot.Children[1].ObservedDigest = ""
	return snapshot
}

func admittedChild(kind, content string) childObservation {
	id := digest.SHA256TextRef(content)
	return childObservation{ArtifactKind: kind, ExpectedDigest: id, ObservedDigest: id, State: ChildAdmitted}
}

func cloneChildren(values []childObservation) []childObservation {
	return append([]childObservation{}, values...)
}
