package projectstatus

import (
	"fmt"
	"reflect"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

var projectStateSet = map[string]struct{}{
	string(StateUninitialized):        {},
	string(StateRecoveryRequired):     {},
	string(StateBlocked):              {},
	string(StateStale):                {},
	string(StateVerificationRequired): {},
}

var issueCodeSet = map[string]struct{}{
	IssueTransactionInvalid:          {},
	IssueTransactionRecoveryRequired: {},
	IssueManifestMissing:             {},
	IssueManifestInvalid:             {},
	IssueChildMissing:                {},
	IssueChildDigestMismatch:         {},
	IssueChildInvalid:                {},
	IssueClosureInvalid:              {},
}

func AdmitStatusOutput(raw any) (Status, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Status{}, fmt.Errorf("project status output must be an object")
	}
	keys := []string{"issueCodes", "manifestId", "nextAction", "nonClaims", "projectId", "projectState", "reportKind", "schemaVersion", "snapshotId", "statusId"}
	if err := admit.KnownKeys(record, keys, "project status output"); err != nil {
		return Status{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], SchemaVersion) || record["reportKind"] != StatusKind {
		return Status{}, fmt.Errorf("project status output identity is invalid")
	}
	statusID, err := admit.SHA256Ref(record["statusId"], "project status statusId")
	if err != nil {
		return Status{}, err
	}
	snapshotID, err := admit.SHA256Ref(record["snapshotId"], "project status snapshotId")
	if err != nil {
		return Status{}, err
	}
	stateText, err := admit.Enum(record["projectState"], projectStateSet, "project status projectState")
	if err != nil {
		return Status{}, err
	}
	projectID, err := nullableRuleID(record["projectId"], "project status projectId")
	if err != nil {
		return Status{}, err
	}
	manifestID, err := nullableSHA256Ref(record["manifestId"], "project status manifestId")
	if err != nil {
		return Status{}, err
	}
	issues, err := admitIssueCodes(record["issueCodes"], "project status issueCodes")
	if err != nil {
		return Status{}, err
	}
	if err := admitBoundaryNonClaims(record["nonClaims"]); err != nil {
		return Status{}, err
	}
	action, err := admitAction(record["nextAction"])
	if err != nil {
		return Status{}, err
	}
	status := Status{
		IssueCodes: issues, ManifestID: manifestID, NextAction: action,
		ProjectID: projectID, ProjectState: ProjectState(stateText),
		SnapshotID: snapshotID, StatusID: statusID,
	}
	if err := validateStatusRelations(status); err != nil {
		return Status{}, err
	}
	wantID, err := digest.StableJSONSHA256Ref(status.identityValue())
	if err != nil || wantID != status.StatusID {
		return Status{}, fmt.Errorf("project status identity does not match its content")
	}
	if err := validateOutputBytes(status.JSONValue()); err != nil {
		return Status{}, err
	}
	return status, nil
}

func AdmitNextOutput(raw any) (Next, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Next{}, fmt.Errorf("project next-action output must be an object")
	}
	keys := []string{"action", "issueCodes", "nonClaims", "packetId", "packetKind", "projectState", "schemaVersion", "snapshotId", "statusRef"}
	if err := admit.KnownKeys(record, keys, "project next-action output"); err != nil {
		return Next{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], SchemaVersion) || record["packetKind"] != NextKind {
		return Next{}, fmt.Errorf("project next-action output identity is invalid")
	}
	packetID, err := admit.SHA256Ref(record["packetId"], "project next-action packetId")
	if err != nil {
		return Next{}, err
	}
	snapshotID, err := admit.SHA256Ref(record["snapshotId"], "project next-action snapshotId")
	if err != nil {
		return Next{}, err
	}
	statusRef, err := admit.SHA256Ref(record["statusRef"], "project next-action statusRef")
	if err != nil {
		return Next{}, err
	}
	stateText, err := admit.Enum(record["projectState"], projectStateSet, "project next-action projectState")
	if err != nil {
		return Next{}, err
	}
	issues, err := admitIssueCodes(record["issueCodes"], "project next-action issueCodes")
	if err != nil {
		return Next{}, err
	}
	if err := admitBoundaryNonClaims(record["nonClaims"]); err != nil {
		return Next{}, err
	}
	action, err := admitAction(record["action"])
	if err != nil {
		return Next{}, err
	}
	next := Next{
		Action: action, IssueCodes: issues, PacketID: packetID,
		ProjectState: ProjectState(stateText), SnapshotID: snapshotID, StatusRef: statusRef,
	}
	if err := validateStateAction(next.ProjectState, next.Action, next.IssueCodes); err != nil {
		return Next{}, err
	}
	wantID, err := digest.StableJSONSHA256Ref(next.identityValue())
	if err != nil || wantID != next.PacketID {
		return Next{}, fmt.Errorf("project next-action identity does not match its content")
	}
	if err := validateOutputBytes(next.JSONValue()); err != nil {
		return Next{}, err
	}
	return next, nil
}

func admitAction(raw any) (NextAction, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return NextAction{}, fmt.Errorf("project next action must be an object")
	}
	keys := []string{"actionClass", "actionId", "commandRoute", "contextRef", "executable", "requiredDecision"}
	if err := admit.KnownKeys(record, keys, "project next action"); err != nil {
		return NextAction{}, err
	}
	actionClass, err := admit.RuleID(record["actionClass"], "project next action actionClass")
	if err != nil {
		return NextAction{}, err
	}
	actionID, err := admit.RuleID(record["actionId"], "project next action actionId")
	if err != nil {
		return NextAction{}, err
	}
	if actionID != "proofkit.project-status.action."+actionClass {
		return NextAction{}, fmt.Errorf("project next action identity is invalid")
	}
	executable, ok := record["executable"].(bool)
	if !ok || executable {
		return NextAction{}, fmt.Errorf("project next action must be non-executable")
	}
	route, err := admitRoute(record["commandRoute"])
	if err != nil {
		return NextAction{}, err
	}
	contextRef, err := nullableSHA256Ref(record["contextRef"], "project next action contextRef")
	if err != nil {
		return NextAction{}, err
	}
	requiredDecision, err := nullableRuleID(record["requiredDecision"], "project next action requiredDecision")
	if err != nil {
		return NextAction{}, err
	}
	return NextAction{
		ActionClass: actionClass, ActionID: actionID, CommandRoute: route,
		ContextRef: contextRef, Executable: false, RequiredDecision: requiredDecision,
	}, nil
}

func admitRoute(raw any) ([]string, error) {
	values, ok := raw.([]any)
	if !ok || len(values) > 4 {
		return nil, fmt.Errorf("project next action commandRoute is invalid")
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		token, err := admit.RuleID(value, "project next action commandRoute token")
		if err != nil {
			return nil, err
		}
		result = append(result, token)
	}
	return result, nil
}

func validateStatusRelations(status Status) error {
	if status.ProjectID == "" && status.ManifestID != "" {
		return fmt.Errorf("project status manifest requires project identity")
	}
	if status.ProjectID != "" && status.ManifestID == "" {
		return fmt.Errorf("project status project identity requires manifest identity")
	}
	if err := validateStateAction(status.ProjectState, status.NextAction, status.IssueCodes); err != nil {
		return err
	}
	switch status.ProjectState {
	case StateUninitialized, StateRecoveryRequired:
		if status.ProjectID != "" || status.ManifestID != "" {
			return fmt.Errorf("project status identity is inconsistent with its state")
		}
	case StateBlocked:
		manifestOnly := reflect.DeepEqual(status.IssueCodes, []string{IssueManifestInvalid}) || reflect.DeepEqual(status.IssueCodes, []string{IssueTransactionInvalid})
		if manifestOnly != (status.ProjectID == "" && status.ManifestID == "") {
			return fmt.Errorf("project blocked identity is inconsistent with its issues")
		}
	case StateStale, StateVerificationRequired:
		if status.ProjectID == "" || status.ManifestID == "" || status.NextAction.ContextRef != status.ManifestID {
			return fmt.Errorf("project status manifest context is inconsistent with its state")
		}
	}
	return nil
}

func validateStateAction(state ProjectState, action NextAction, issues []string) error {
	want, err := canonicalAction(state, issues, action.ContextRef)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(action, want) {
		return fmt.Errorf("project state and next action do not match")
	}
	return nil
}

func admitIssueCodes(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok || len(values) > MaximumIssueCodes {
		return nil, fmt.Errorf("%s are invalid", context)
	}
	result := make([]string, 0, len(values))
	previous := ""
	for _, rawValue := range values {
		value, err := admit.RuleID(rawValue, context)
		if err != nil {
			return nil, err
		}
		if _, ok := issueCodeSet[value]; !ok || previous != "" && previous >= value {
			return nil, fmt.Errorf("%s must be sorted, unique, and supported", context)
		}
		previous = value
		result = append(result, value)
	}
	return result, nil
}

func allIssuesIn(values []string, admitted ...string) bool {
	set := map[string]struct{}{}
	for _, value := range admitted {
		set[value] = struct{}{}
	}
	for _, value := range values {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	return true
}

func containsAnyIssue(values []string, candidates ...string) bool {
	for _, value := range values {
		for _, candidate := range candidates {
			if value == candidate {
				return true
			}
		}
	}
	return false
}

func admitBoundaryNonClaims(raw any) error {
	values, err := admit.PreserveSortedTextArray(raw, "project status nonClaims", false)
	if err != nil || !reflect.DeepEqual(values, boundaryNonClaims) {
		return fmt.Errorf("project status nonClaims are invalid")
	}
	return nil
}

func nullableRuleID(raw any, context string) (string, error) {
	if raw == nil {
		return "", nil
	}
	return admit.RuleID(raw, context)
}

func nullableSHA256Ref(raw any, context string) (string, error) {
	if raw == nil {
		return "", nil
	}
	return admit.SHA256Ref(raw, context)
}

func validateOutputBytes(value map[string]any) error {
	content, err := stablejson.Marshal(value)
	if err != nil {
		return err
	}
	if len(content) > MaximumOutputBytes {
		return fmt.Errorf("project status output exceeds its byte limit")
	}
	return nil
}
