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

const maximumRecoveryActionBytes = 512

type recoveryActionRecord struct {
	Action        string
	TransactionID string
}

func selectRecoveryAction(root *os.Root, transactionID, action string) error {
	selected, exists, err := readRecoveryAction(root)
	if err != nil {
		return err
	}
	if exists {
		if selected.Action != action || selected.TransactionID != transactionID {
			return fmt.Errorf("repository transaction recovery action contradicts durable state")
		}
		return nil
	}
	record := recoveryActionRecord{Action: action, TransactionID: transactionID}
	content, err := stablejson.Marshal(recoveryActionValue(record))
	if err != nil || len(content) > maximumRecoveryActionBytes {
		return fmt.Errorf("encode repository transaction recovery action")
	}
	return writeAtomicOwnedFile(root, recoveryActionPath, recoveryActionTemp, content, 0o600)
}

func readRecoveryAction(root *os.Root) (recoveryActionRecord, bool, error) {
	exists, err := pathExists(root, recoveryActionPath)
	if err != nil || !exists {
		return recoveryActionRecord{}, false, err
	}
	content, err := readOwnedFile(root, recoveryActionPath, maximumRecoveryActionBytes)
	if err != nil {
		return recoveryActionRecord{}, false, err
	}
	raw, err := admission.DecodeJSON(bytes.NewReader(content), maximumRecoveryActionBytes)
	if err != nil {
		return recoveryActionRecord{}, false, fmt.Errorf("admit repository transaction recovery action")
	}
	record, err := admitRecoveryAction(raw)
	if err != nil {
		return recoveryActionRecord{}, false, err
	}
	canonical, err := stablejson.Marshal(recoveryActionValue(record))
	if err != nil || !bytes.Equal(content, canonical) {
		return recoveryActionRecord{}, false, fmt.Errorf("repository transaction recovery action is not canonical")
	}
	return record, true, nil
}

func admitRecoveryAction(raw any) (recoveryActionRecord, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return recoveryActionRecord{}, fmt.Errorf("repository transaction recovery action must be an object")
	}
	if err := admit.KnownKeys(record, []string{"action", "actionKind", "schemaVersion", "transactionId"}, "repository transaction recovery action"); err != nil {
		return recoveryActionRecord{}, err
	}
	if record["actionKind"] != "proofkit.repository-recovery-action" || !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return recoveryActionRecord{}, fmt.Errorf("repository transaction recovery action identity is invalid")
	}
	action, err := admit.Enum(record["action"], map[string]struct{}{RecoveryResume: {}, RecoveryRollback: {}}, "repository transaction recovery action")
	if err != nil {
		return recoveryActionRecord{}, err
	}
	transactionID, err := admit.SHA256Ref(record["transactionId"], "repository transaction recovery action transactionId")
	if err != nil {
		return recoveryActionRecord{}, err
	}
	return recoveryActionRecord{Action: action, TransactionID: transactionID}, nil
}

func recoveryActionValue(record recoveryActionRecord) map[string]any {
	return map[string]any{
		"action":        record.Action,
		"actionKind":    "proofkit.repository-recovery-action",
		"schemaVersion": json.Number("1"),
		"transactionId": record.TransactionID,
	}
}
