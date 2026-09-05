package repositorytransaction

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	maximumTerminalReceiptBytes = 2048
	terminalReceiptName         = "terminal.json"
	terminalReceiptTempName     = "terminal.tmp"
)

type terminalReceipt struct {
	AppliedCount   int
	DesiredStateID string
	FailureClass   string
	RecoveredBy    string
	State          string
	TransactionID  string
}

// ReadTerminalResult returns the retained terminal result for one exact
// transaction without consuming it. Historical inspection does not establish
// current target state or authorize acknowledgement replay; use ReplayApplied.
func ReadTerminalResult(ctx context.Context, rootPath, transactionID string) (Result, error) {
	admittedID, err := admit.SHA256Ref(transactionID, "repository transaction terminal transactionId")
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("read repository transaction terminal result cancelled: %w", err)
	}
	root, _, err := openRepository(rootPath)
	if err != nil {
		return Result{}, err
	}
	defer root.Close()
	lock, exists, err := acquireExistingTransactionLock(root)
	if err != nil {
		return Result{}, err
	}
	if !exists {
		return Result{}, fmt.Errorf("repository transaction terminal result is absent")
	}
	defer lock.release()
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("read repository transaction terminal result cancelled: %w", err)
	}
	receipt, err := readRetainedTerminalReceipt(root, admittedID)
	return receipt.result(), err
}

func readRetainedTerminalReceipt(root *os.Root, admittedID string) (terminalReceipt, error) {
	entries, err := controlEntries(root)
	if err != nil {
		return terminalReceipt{}, err
	}
	terminal, found, err := findTerminalControlEntry(entries)
	if err != nil {
		return terminalReceipt{}, err
	}
	if !found || terminal.TransactionID != admittedID {
		return terminalReceipt{}, ErrReplayMismatch
	}
	path := ControlDirectory + "/" + terminal.Entry.Name()
	children, err := transactionEntries(root, path)
	if err != nil || len(children) != 1 || children[0].Name() != terminalReceiptName {
		return terminalReceipt{}, fmt.Errorf("repository transaction terminal result is invalid")
	}
	receipt, err := loadTerminalReceipt(root, path)
	if err != nil || receipt.TransactionID != admittedID || receipt.State != terminal.State {
		return terminalReceipt{}, fmt.Errorf("repository transaction terminal result is invalid")
	}
	return receipt, nil
}

func (receipt terminalReceipt) result() Result {
	return Result{
		AppliedCount:      receipt.AppliedCount,
		AppliedCountKnown: true,
		FailureClass:      receipt.FailureClass,
		RecoveredBy:       receipt.RecoveredBy,
		State:             receipt.State,
		TransactionID:     receipt.TransactionID,
	}
}

func ensureTerminalReceipt(root *os.Root, plan Plan, result Result) error {
	want, err := terminalReceiptFromResult(plan, result)
	if err != nil {
		return err
	}
	path := activeDirectory + "/" + terminalReceiptName
	if exists, err := pathExists(root, path); err != nil {
		return err
	} else if exists {
		got, err := loadTerminalReceipt(root, activeDirectory)
		if err != nil || !terminalReceiptMatchesPlan(got, want) {
			return fmt.Errorf("repository transaction terminal receipt contradicts terminal state")
		}
		return discardOwnedTemporaryFile(root, activeDirectory+"/"+terminalReceiptTempName)
	}
	content, err := stablejson.Marshal(terminalReceiptValue(want))
	if err != nil || len(content) > maximumTerminalReceiptBytes {
		return fmt.Errorf("encode repository transaction terminal receipt")
	}
	return writeAtomicOwnedFile(root, path, activeDirectory+"/"+terminalReceiptTempName, content, 0o600)
}

func terminalReceiptFromResult(plan Plan, result Result) (terminalReceipt, error) {
	if result.State != StateApplied && result.State != StateRolledBack {
		return terminalReceipt{}, fmt.Errorf("repository transaction terminal state is invalid")
	}
	if err := validateResultRelation(result); err != nil || !result.AppliedCountKnown || result.TransactionID != plan.TransactionID || result.AppliedCount != prefixForState(plan, result.State) {
		return terminalReceipt{}, fmt.Errorf("repository transaction terminal result does not match its plan")
	}
	return terminalReceipt{
		AppliedCount:   result.AppliedCount,
		DesiredStateID: plan.DesiredStateID,
		FailureClass:   result.FailureClass,
		RecoveredBy:    result.RecoveredBy,
		State:          result.State,
		TransactionID:  result.TransactionID,
	}, nil
}

func loadTerminalReceipt(root *os.Root, directory string) (terminalReceipt, error) {
	content, err := readOwnedFile(root, directory+"/"+terminalReceiptName, maximumTerminalReceiptBytes)
	if err != nil {
		return terminalReceipt{}, err
	}
	raw, err := admission.DecodeJSON(bytes.NewReader(content), maximumTerminalReceiptBytes)
	if err != nil {
		return terminalReceipt{}, fmt.Errorf("admit repository transaction terminal receipt")
	}
	receipt, err := admitTerminalReceipt(raw)
	if err != nil {
		return terminalReceipt{}, err
	}
	canonical, err := stablejson.Marshal(terminalReceiptValue(receipt))
	if err != nil || !bytes.Equal(content, canonical) {
		return terminalReceipt{}, fmt.Errorf("repository transaction terminal receipt is not canonical")
	}
	return receipt, nil
}

func admitTerminalReceipt(raw any) (terminalReceipt, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return terminalReceipt{}, fmt.Errorf("repository transaction terminal receipt must be an object")
	}
	bound := admit.JSONNumberEquals(record["schemaVersion"], 2)
	keys := []string{"appliedCount", "failureClass", "recoveredBy", "schemaVersion", "state", "terminalKind", "transactionId"}
	if bound {
		keys = append(keys, "desiredStateId")
	}
	if err := admit.KnownKeys(record, keys, "repository transaction terminal receipt"); err != nil {
		return terminalReceipt{}, err
	}
	if record["terminalKind"] != "proofkit.repository-terminal-receipt" || !bound && !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return terminalReceipt{}, fmt.Errorf("repository transaction terminal receipt identity is invalid")
	}
	desiredStateID := ""
	if bound {
		var err error
		desiredStateID, err = admit.SHA256Ref(record["desiredStateId"], "repository transaction terminal receipt desiredStateId")
		if err != nil {
			return terminalReceipt{}, err
		}
	}
	appliedCount, err := admit.CanonicalInteger(record["appliedCount"], "repository transaction terminal receipt appliedCount")
	if err != nil || appliedCount < 0 || appliedCount > MaximumOperations {
		return terminalReceipt{}, fmt.Errorf("repository transaction terminal receipt appliedCount is invalid")
	}
	state, err := admit.Enum(record["state"], map[string]struct{}{StateApplied: {}, StateRolledBack: {}}, "repository transaction terminal receipt state")
	if err != nil {
		return terminalReceipt{}, err
	}
	if state == StateRolledBack && appliedCount != 0 {
		return terminalReceipt{}, fmt.Errorf("rolled-back repository transaction terminal receipt must have zero appliedCount")
	}
	transactionID, err := admit.SHA256Ref(record["transactionId"], "repository transaction terminal receipt transactionId")
	if err != nil {
		return terminalReceipt{}, err
	}
	failureClass := ""
	if record["failureClass"] != nil {
		failureClass, err = admit.NonEmptyText(record["failureClass"], "repository transaction terminal receipt failureClass")
		if err != nil {
			return terminalReceipt{}, err
		}
	}
	recoveredBy := ""
	if record["recoveredBy"] != nil {
		recoveredBy, err = admit.Enum(record["recoveredBy"], map[string]struct{}{RecoveryResume: {}, RecoveryRollback: {}}, "repository transaction terminal receipt recoveredBy")
		if err != nil {
			return terminalReceipt{}, err
		}
	}
	result := Result{
		AppliedCount:      int(appliedCount),
		AppliedCountKnown: true,
		FailureClass:      failureClass,
		RecoveredBy:       recoveredBy,
		State:             state,
		TransactionID:     transactionID,
	}
	if err := validateResultRelation(result); err != nil {
		return terminalReceipt{}, fmt.Errorf("repository transaction terminal receipt result is invalid")
	}
	return terminalReceipt{AppliedCount: int(appliedCount), DesiredStateID: desiredStateID, FailureClass: failureClass, RecoveredBy: recoveredBy, State: state, TransactionID: transactionID}, nil
}

func terminalReceiptValue(receipt terminalReceipt) map[string]any {
	value := map[string]any{
		"appliedCount":  json.Number(intString(receipt.AppliedCount)),
		"failureClass":  nullableText(receipt.FailureClass),
		"recoveredBy":   nullableText(receipt.RecoveredBy),
		"schemaVersion": json.Number("1"),
		"state":         receipt.State,
		"terminalKind":  "proofkit.repository-terminal-receipt",
		"transactionId": receipt.TransactionID,
	}
	if receipt.DesiredStateID != "" {
		value["schemaVersion"] = json.Number("2")
		value["desiredStateId"] = receipt.DesiredStateID
	}
	return value
}

// Legacy receipts retain their historical fields during recovery; only a bound
// generation-2 receipt can subsequently establish the desired-state relation.
func terminalReceiptMatchesPlan(receipt, expected terminalReceipt) bool {
	if receipt.DesiredStateID == "" {
		expected.DesiredStateID = ""
	}
	return receipt == expected
}
