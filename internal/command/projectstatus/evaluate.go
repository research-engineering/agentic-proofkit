package projectstatus

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func evaluate(snapshot inspectionSnapshot) (Status, error) {
	if err := validateSnapshot(snapshot); err != nil {
		return Status{}, err
	}
	id, err := snapshotID(snapshot)
	if err != nil {
		return Status{}, fmt.Errorf("derive project status snapshot identity")
	}
	state, issues := classify(snapshot)
	action, err := canonicalAction(state, issues, actionContext(state, snapshot))
	if err != nil {
		return Status{}, fmt.Errorf("derive project status next action: %w", err)
	}
	status := Status{
		IssueCodes:   issues,
		ManifestID:   snapshot.Manifest.ManifestID,
		NextAction:   action,
		ProjectID:    snapshot.ProjectID,
		ProjectState: state,
		SnapshotID:   id,
	}
	statusID, err := digest.StableJSONSHA256Ref(status.identityValue())
	if err != nil {
		return Status{}, fmt.Errorf("derive project status identity")
	}
	status.StatusID = statusID
	if _, err := AdmitStatusOutput(status.JSONValue()); err != nil {
		return Status{}, fmt.Errorf("admit generated project status: %w", err)
	}
	return status, nil
}

func NextFromStatus(status Status) (Next, error) {
	admitted, err := AdmitStatusOutput(status.JSONValue())
	if err != nil {
		return Next{}, err
	}
	next := Next{
		Action:       admitted.NextAction,
		IssueCodes:   append([]string{}, admitted.IssueCodes...),
		ProjectState: admitted.ProjectState,
		SnapshotID:   admitted.SnapshotID,
		StatusRef:    admitted.StatusID,
	}
	id, err := digest.StableJSONSHA256Ref(next.identityValue())
	if err != nil {
		return Next{}, fmt.Errorf("derive project next-action identity")
	}
	next.PacketID = id
	if _, err := AdmitNextOutput(next.JSONValue()); err != nil {
		return Next{}, fmt.Errorf("admit generated project next action: %w", err)
	}
	return next, nil
}

func classify(snapshot inspectionSnapshot) (ProjectState, []string) {
	if snapshot.Transaction.State == TransactionInvalid {
		return StateBlocked, []string{IssueTransactionInvalid}
	}
	if snapshot.Transaction.State == TransactionRecoverable {
		return StateRecoveryRequired, []string{IssueTransactionRecoveryRequired}
	}
	if snapshot.Manifest.State == ManifestAbsent {
		return StateUninitialized, []string{IssueManifestMissing}
	}
	if snapshot.Manifest.State == ManifestInvalid {
		return StateBlocked, []string{IssueManifestInvalid}
	}
	issues := make([]string, 0, len(snapshot.Children)+1)
	invalid := false
	stale := false
	for _, child := range snapshot.Children {
		switch child.State {
		case ChildMissing:
			issues = append(issues, IssueChildMissing)
			stale = true
		case ChildDigestMismatch:
			issues = append(issues, IssueChildDigestMismatch)
			stale = true
		case ChildInvalid:
			issues = append(issues, IssueChildInvalid)
			invalid = true
		}
	}
	if snapshot.ClosureState == ClosureInvalid {
		issues = append(issues, IssueClosureInvalid)
		invalid = true
	}
	issues = sortedUnique(issues)
	if invalid {
		return StateBlocked, issues
	}
	if stale {
		return StateStale, issues
	}
	return StateVerificationRequired, issues
}

func actionContext(state ProjectState, snapshot inspectionSnapshot) string {
	switch state {
	case StateRecoveryRequired:
		return snapshot.Transaction.TransactionID
	case StateStale, StateVerificationRequired:
		return snapshot.Manifest.ManifestID
	default:
		return ""
	}
}

func canonicalAction(state ProjectState, issues []string, contextRef string) (NextAction, error) {
	action := NextAction{CommandRoute: []string{}, Executable: false}
	switch state {
	case StateBlocked:
		if contextRef != "" || len(issues) == 0 {
			return NextAction{}, fmt.Errorf("project blocked issue set is invalid")
		}
		if reflect.DeepEqual(issues, []string{IssueTransactionInvalid}) {
			action.ActionClass = ActionRepairControlState
		} else if reflect.DeepEqual(issues, []string{IssueManifestInvalid}) || reflect.DeepEqual(issues, []string{IssueClosureInvalid}) ||
			allIssuesIn(issues, IssueChildInvalid, IssueChildMissing, IssueChildDigestMismatch) && containsAnyIssue(issues, IssueChildInvalid) {
			action.ActionClass = ActionRepairProjectRecords
		} else {
			return NextAction{}, fmt.Errorf("project blocked issue set is invalid")
		}
	case StateRecoveryRequired:
		if !reflect.DeepEqual(issues, []string{IssueTransactionRecoveryRequired}) || contextRef == "" {
			return NextAction{}, fmt.Errorf("project recovery-required projection is invalid")
		}
		action.ActionClass = ActionChooseRecovery
		action.CommandRoute = []string{"adopt", "materialize", "recover"}
		action.ContextRef = contextRef
		action.RequiredDecision = "resume_or_rollback"
	case StateUninitialized:
		if !reflect.DeepEqual(issues, []string{IssueManifestMissing}) || contextRef != "" {
			return NextAction{}, fmt.Errorf("project uninitialized issue set is invalid")
		}
		action.ActionClass = ActionChooseAdoptionMode
		action.CommandRoute = []string{"adopt", "plan"}
		action.RequiredDecision = "adoption_mode"
	case StateStale:
		if len(issues) == 0 || !allIssuesIn(issues, IssueChildMissing, IssueChildDigestMismatch) || contextRef == "" {
			return NextAction{}, fmt.Errorf("project stale projection is invalid")
		}
		action.ActionClass = ActionRematerializeProject
		action.CommandRoute = []string{"adopt", "materialize", "plan"}
		action.ContextRef = contextRef
	case StateVerificationRequired:
		if len(issues) != 0 || contextRef == "" {
			return NextAction{}, fmt.Errorf("project verification-required projection is invalid")
		}
		action.ActionClass = ActionRunRepositoryVerification
		action.ContextRef = contextRef
	default:
		return NextAction{}, fmt.Errorf("project state is unsupported")
	}
	action.ActionID = "proofkit.project-status.action." + action.ActionClass
	return action, nil
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return append([]string{}, result...)
}
