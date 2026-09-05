package repositorytransaction

import (
	"encoding/json"
	"io/fs"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	ControlRoot      = ".agentic-proofkit"
	ControlDirectory = ControlRoot + "/transactions"

	MaximumOperations     = 32
	MaximumFileBytes      = 1 << 20
	MaximumAggregateBytes = 8 << 20
	MaximumJournalBytes   = 256 << 10
)

const (
	ActionCreate    = "create"
	ActionReplace   = "replace"
	ActionUnchanged = "unchanged"
)

const (
	StateApplied           = "applied"
	StateAlreadySatisfied  = "already_satisfied"
	StateCleanupRequired   = "cleanup_required"
	StateDurabilityUnknown = "durability_unknown"
	StateRecoveryRequired  = "recovery_required"
	StateRolledBack        = "rolled_back"
)

const (
	RecoveryResume   = "resume"
	RecoveryRollback = "rollback"
)

var boundaryNonClaims = []string{
	"Public transaction plan re-admission proves canonical paths and byte identities, not executable payload bytes; re-admitted plans cannot be applied.",
	"Repository transactions do not establish semantic correctness, owner approval, Git cleanliness, merge authority, release authority, rollout, or production readiness.",
	"Repository transactions do not prove power-loss durability or protection from non-cooperative same-user writers.",
	"Repository transactions do not provide simultaneous multi-file visibility to arbitrary readers.",
}

type Target struct {
	Content []byte
	Mode    fs.FileMode
	Path    string
}

type Snapshot struct {
	ByteCount int64
	Exists    bool
	Mode      fs.FileMode
	SHA256    string
}

type Operation struct {
	Action        string
	After         Snapshot
	Before        Snapshot
	Path          string
	afterContent  []byte
	beforeContent []byte
}

type Plan struct {
	CreatedDirectories []string
	DesiredStateID     string
	Operations         []Operation
	RootID             string
	TransactionID      string

	constructedTransactionID string
}

type Result struct {
	AppliedCount      int
	AppliedCountKnown bool
	FailureClass      string
	RecoveredBy       string
	State             string
	TransactionID     string
}

type pendingState struct {
	Exists        bool
	TransactionID string
}

// BeforeContent returns a defensive copy of the target bytes captured while
// building this in-memory plan. The bytes are intentionally absent from the
// public JSON projection.
func (plan Plan) BeforeContent(operationIndex int) ([]byte, bool) {
	if operationIndex < 0 || operationIndex >= len(plan.Operations) || !plan.Operations[operationIndex].Before.Exists {
		return nil, false
	}
	return append([]byte(nil), plan.Operations[operationIndex].beforeContent...), true
}

func clonePlan(plan Plan) Plan {
	clone := plan
	clone.CreatedDirectories = append([]string(nil), plan.CreatedDirectories...)
	clone.Operations = append([]Operation(nil), plan.Operations...)
	for index := range clone.Operations {
		clone.Operations[index].afterContent = append([]byte(nil), plan.Operations[index].afterContent...)
		clone.Operations[index].beforeContent = append([]byte(nil), plan.Operations[index].beforeContent...)
	}
	return clone
}

func (plan Plan) JSONValue() map[string]any {
	operations := make([]any, 0, len(plan.Operations))
	for _, operation := range plan.Operations {
		operations = append(operations, operationValue(operation))
	}
	return map[string]any{
		"createdDirectories": admit.StringSliceToAny(plan.CreatedDirectories),
		"desiredStateId":     plan.DesiredStateID,
		"nonClaims":          admit.StringSliceToAny(boundaryNonClaims),
		"operations":         operations,
		"rootId":             plan.RootID,
		"schemaVersion":      json.Number("1"),
		"transactionId":      plan.TransactionID,
		"transactionKind":    "proofkit.repository-write-plan",
	}
}

func (result Result) JSONValue() map[string]any {
	var appliedCount any
	if result.AppliedCountKnown {
		appliedCount = json.Number(intString(result.AppliedCount))
	}
	return map[string]any{
		"appliedCount":  appliedCount,
		"failureClass":  nullableText(result.FailureClass),
		"nonClaims":     admit.StringSliceToAny(boundaryNonClaims),
		"recoveredBy":   nullableText(result.RecoveredBy),
		"schemaVersion": json.Number("1"),
		"state":         result.State,
		"transactionId": nullableText(result.TransactionID),
	}
}

func operationValue(operation Operation) map[string]any {
	return map[string]any{
		"action": operation.Action,
		"after":  snapshotValue(operation.After),
		"before": snapshotValue(operation.Before),
		"path":   operation.Path,
	}
}

func snapshotValue(snapshot Snapshot) map[string]any {
	return map[string]any{
		"byteCount": json.Number(int64String(snapshot.ByteCount)),
		"exists":    snapshot.Exists,
		"mode":      modeText(snapshot.Mode),
		"sha256":    nullableText(snapshot.SHA256),
	}
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}
