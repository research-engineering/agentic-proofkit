package repositorytransaction

import (
	"bytes"
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
)

type terminalReceipt struct {
	AppliedCount  int
	State         string
	TransactionID string
}

func ensureTerminalReceipt(root *os.Root, plan Plan, state string) error {
	want := terminalReceipt{AppliedCount: prefixForState(plan, state), State: state, TransactionID: plan.TransactionID}
	path := activeDirectory + "/" + terminalReceiptName
	if exists, err := pathExists(root, path); err != nil {
		return err
	} else if exists {
		got, err := loadTerminalReceipt(root, activeDirectory)
		if err != nil || got != want {
			return fmt.Errorf("repository transaction terminal receipt contradicts terminal state")
		}
		return nil
	}
	content, err := stablejson.Marshal(terminalReceiptValue(want))
	if err != nil || len(content) > maximumTerminalReceiptBytes {
		return fmt.Errorf("encode repository transaction terminal receipt")
	}
	return writeOwnedFile(root, path, content, 0o600)
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
	if err := admit.KnownKeys(record, []string{"appliedCount", "schemaVersion", "state", "terminalKind", "transactionId"}, "repository transaction terminal receipt"); err != nil {
		return terminalReceipt{}, err
	}
	if record["terminalKind"] != "proofkit.repository-terminal-receipt" || !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return terminalReceipt{}, fmt.Errorf("repository transaction terminal receipt identity is invalid")
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
	return terminalReceipt{AppliedCount: int(appliedCount), State: state, TransactionID: transactionID}, nil
}

func terminalReceiptValue(receipt terminalReceipt) map[string]any {
	return map[string]any{
		"appliedCount":  json.Number(intString(receipt.AppliedCount)),
		"schemaVersion": json.Number("1"),
		"state":         receipt.State,
		"terminalKind":  "proofkit.repository-terminal-receipt",
		"transactionId": receipt.TransactionID,
	}
}
