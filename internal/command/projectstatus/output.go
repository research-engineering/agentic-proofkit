package projectstatus

import (
	"encoding/json"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func (status Status) JSONValue() map[string]any {
	value := status.identityValue()
	value["statusId"] = status.StatusID
	return value
}

func (status Status) identityValue() map[string]any {
	return map[string]any{
		"issueCodes":    admit.StringSliceToAny(status.IssueCodes),
		"manifestId":    nullable(status.ManifestID),
		"nextAction":    status.NextAction.JSONValue(),
		"nonClaims":     admit.StringSliceToAny(boundaryNonClaims),
		"projectId":     nullable(status.ProjectID),
		"projectState":  string(status.ProjectState),
		"reportKind":    StatusKind,
		"schemaVersion": json.Number("1"),
		"snapshotId":    status.SnapshotID,
	}
}

func (next Next) JSONValue() map[string]any {
	value := next.identityValue()
	value["packetId"] = next.PacketID
	return value
}

func (next Next) identityValue() map[string]any {
	return map[string]any{
		"action":        next.Action.JSONValue(),
		"issueCodes":    admit.StringSliceToAny(next.IssueCodes),
		"nonClaims":     admit.StringSliceToAny(boundaryNonClaims),
		"packetKind":    NextKind,
		"projectState":  string(next.ProjectState),
		"schemaVersion": json.Number("1"),
		"snapshotId":    next.SnapshotID,
		"statusRef":     next.StatusRef,
	}
}

func (action NextAction) JSONValue() map[string]any {
	route := make([]any, len(action.CommandRoute))
	for index, token := range action.CommandRoute {
		route[index] = token
	}
	return map[string]any{
		"actionClass":      action.ActionClass,
		"actionId":         action.ActionID,
		"commandRoute":     route,
		"contextRef":       nullable(action.ContextRef),
		"executable":       action.Executable,
		"requiredDecision": nullable(action.RequiredDecision),
	}
}
