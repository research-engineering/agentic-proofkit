// Package adoptionmaterialization owns the explicit promotion of admitted
// adoption records into a repository-bound, recoverable write transaction.
package adoptionmaterialization

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

const (
	SchemaVersion = 1
	RequestKind   = "proofkit.adoption-materialization-request"
	PlanKind      = "proofkit.adoption-materialization-plan"
	ReceiptKind   = "proofkit.adoption-materialization-receipt"

	ProjectManifestPath = "proofkit/project.v1.json"

	MaximumRequirementSources = repositorytransaction.MaximumOperations - 3
	MaximumOutputBytes        = 256 << 10
	MaximumTextBytes          = 16 << 10
	MaximumTextLines          = 96
)

const (
	ArtifactRequirementSource  = "requirement_source"
	ArtifactRequirementBinding = "requirement_proof_binding"
	ArtifactTestInventory      = "test_evidence_inventory"
	ArtifactProjectManifest    = "project_routing_manifest"
)

const (
	OperationPlan    = "plan"
	OperationApply   = "apply"
	OperationRecover = "recover"
)

const (
	ReceiptStateBlocked           = "blocked"
	ReceiptStateCleanupRequired   = "cleanup_required"
	ReceiptStateDurabilityUnknown = "durability_unknown"
	ReceiptStateFailed            = "failed"
	ReceiptStatePassed            = "passed"
	ReceiptStateRecoveryRequired  = "recovery_required"
)

var boundaryNonClaims = []string{
	"Adoption materialization does not authenticate caller declarations or approve requirement meaning, proof adequacy, merge, release, rollout, or production readiness.",
	"Adoption materialization provides recoverable ordered-prefix writes for cooperative writers, not simultaneous multi-file visibility or power-loss durability.",
	"The project routing manifest names canonical records but does not replace their semantic owners or prove their continuing validity.",
}

type Request struct {
	Binding       requirementbinding.Input
	BindingPath   string
	Inventory     testevidenceinventory.Inventory
	InventoryPath string
	NonClaims     []string
	ProjectID     string
	RequestID     string
	SourceIntent  string
	SourcePlanID  string
	Sources       []requirementsourceadmission.Source
}

type artifact struct {
	Content []byte
	ID      string
	Kind    string
	Path    string
}

type Plan struct {
	Manifest     Manifest
	NonClaims    []string
	ProjectID    string
	RequestID    string
	SourceIntent string
	SourcePlanID string
	Transaction  repositorytransaction.Plan
}

type Receipt struct {
	ExpectedDesiredStateID string
	ExpectedTransactionID  string
	FailureClass           string
	NonClaims              []string
	Operation              string
	ReceiptID              string
	State                  string
	TransactionResult      *repositorytransaction.Result
}

type Materialization struct {
	Artifacts   []artifact
	Plan        Plan
	Transaction repositorytransaction.Plan
}

func (plan Plan) JSONValue() map[string]any {
	return map[string]any{
		"manifest":      plan.Manifest.JSONValue(),
		"nonClaims":     admit.StringSliceToAny(plan.NonClaims),
		"planKind":      PlanKind,
		"projectId":     plan.ProjectID,
		"requestId":     plan.RequestID,
		"schemaVersion": json.Number("1"),
		"sourceIntent":  plan.SourceIntent,
		"sourcePlanId":  plan.SourcePlanID,
		"state":         "ready",
		"transaction":   plan.Transaction.JSONValue(),
	}
}

func (receipt Receipt) JSONValue() map[string]any {
	value := receipt.identityValue()
	value["receiptId"] = receipt.ReceiptID
	return value
}

func (receipt Receipt) identityValue() map[string]any {
	var transactionResult any
	if receipt.TransactionResult != nil {
		transactionResult = receipt.TransactionResult.JSONValue()
	}
	return map[string]any{
		"expectedDesiredStateId": nullableText(receipt.ExpectedDesiredStateID),
		"expectedTransactionId":  nullableText(receipt.ExpectedTransactionID),
		"failureClass":           nullableText(receipt.FailureClass),
		"nonClaims":              admit.StringSliceToAny(receipt.NonClaims),
		"operation":              receipt.Operation,
		"receiptKind":            ReceiptKind,
		"schemaVersion":          json.Number("1"),
		"state":                  receipt.State,
		"transactionResult":      transactionResult,
	}
}

func newReceipt(operation, state, failureClass, expectedTransactionID, expectedDesiredStateID string, result *repositorytransaction.Result, nonClaims []string) (Receipt, error) {
	receipt := Receipt{
		ExpectedDesiredStateID: expectedDesiredStateID,
		ExpectedTransactionID:  expectedTransactionID,
		FailureClass:           failureClass,
		NonClaims:              mergedNonClaims(nonClaims),
		Operation:              operation,
		State:                  state,
		TransactionResult:      result,
	}
	id, err := digest.StableJSONSHA256Ref(receipt.identityValue())
	if err != nil {
		return Receipt{}, fmt.Errorf("derive adoption materialization receipt identity")
	}
	receipt.ReceiptID = id
	if _, err := AdmitReceiptOutput(receipt.JSONValue()); err != nil {
		return Receipt{}, fmt.Errorf("admit adoption materialization receipt output: %w", err)
	}
	return receipt, nil
}

func mergedNonClaims(caller []string) []string {
	values := append(append([]string{}, boundaryNonClaims...), caller...)
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func sourcePlanCoordinates(plan adoptionplan.Plan) (string, string) {
	return plan.PlanID, plan.Intent
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}
