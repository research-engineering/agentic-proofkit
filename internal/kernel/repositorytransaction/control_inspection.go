package repositorytransaction

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/rootpath"
)

var ErrControlStateChanged = errors.New("repository transaction control state changed during inspection")

const (
	ControlStateClean       = "clean"
	ControlStateRecoverable = "recoverable"
	ControlStateInvalid     = "invalid"
)

// ControlInspection is a read-only projection of the repository transaction
// namespace. TransactionID is present only when recovery identity is known.
type ControlInspection struct {
	EpochID       string
	State         string
	TransactionID string
}

// InspectControlState returns a content-bound transaction-control epoch
// without creating, removing, or rewriting repository state.
func InspectControlState(ctx context.Context, rootPath string) (inspection ControlInspection, returnErr error) {
	lease, err := OpenInspectionLease(ctx, rootPath)
	if err != nil {
		return ControlInspection{}, err
	}
	defer func() {
		if closeErr := lease.Close(); closeErr != nil {
			inspection = ControlInspection{}
			returnErr = fmt.Errorf("close repository transaction inspection: %w", closeErr)
		}
	}()
	return lease.InspectControlState(ctx)
}

func emptyControlObservationID() (string, error) {
	value, err := digest.StableJSONSHA256Ref(map[string]any{
		"controlObservationKind": "proofkit.repository-control-observation",
		"entries":                []any{},
		"schemaVersion":          json.Number("1"),
	})
	if err != nil {
		return "", fmt.Errorf("derive empty repository transaction control observation: %w", err)
	}
	return value, nil
}

func newControlInspection(state, transactionID, observationID string) (ControlInspection, error) {
	epochID, err := digest.StableJSONSHA256Ref(map[string]any{
		"controlEpochKind": "proofkit.repository-control-epoch",
		"observationId":    observationID,
		"schemaVersion":    json.Number("1"),
		"state":            state,
		"transactionId":    nullableText(transactionID),
	})
	if err != nil {
		return ControlInspection{}, fmt.Errorf("derive repository transaction control epoch: %w", err)
	}
	return ControlInspection{EpochID: epochID, State: state, TransactionID: transactionID}, nil
}

func classifyControlState(root *os.Root, rootID string, observation controlObservation) (string, string, error) {
	if observation.Invalid {
		return ControlStateInvalid, "", nil
	}
	entries := observation.Entries
	if len(entries) == 0 {
		return ControlStateClean, "", nil
	}
	terminal, terminalFound, err := findTerminalControlEntry(entries)
	if err != nil {
		return ControlStateInvalid, "", nil
	}
	active := false
	for _, entry := range entries {
		if entry.Name() == "active" && entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			active = true
		}
	}
	if !active {
		if len(entries) != 1 || !terminalFound {
			return ControlStateInvalid, "", nil
		}
		state, validationErr := terminalControlState(root, terminal)
		if operationalErr := controlInspectionOperationalError(validationErr); operationalErr != nil {
			return "", "", operationalErr
		}
		if validationErr != nil || state == ControlStateInvalid {
			return ControlStateInvalid, "", nil
		}
		if state == ControlStateRecoverable {
			return state, terminal.TransactionID, nil
		}
		return ControlStateClean, "", nil
	}
	if len(entries) > 2 {
		return ControlStateInvalid, "", nil
	}
	if terminalFound {
		state, validationErr := terminalControlState(root, terminal)
		if operationalErr := controlInspectionOperationalError(validationErr); operationalErr != nil {
			return "", "", operationalErr
		}
		if validationErr != nil || state != ControlStateClean {
			return ControlStateInvalid, "", nil
		}
	}
	if err := validatePrivateDirectory(root, activeDirectory, 0o700); err != nil {
		if operationalErr := controlInspectionOperationalError(err); operationalErr != nil {
			return "", "", operationalErr
		}
		return ControlStateInvalid, "", nil
	}
	plan, err := loadJournal(root)
	if err != nil {
		if operationalErr := controlInspectionOperationalError(err); operationalErr != nil {
			return "", "", operationalErr
		}
		var admitted bool
		plan, admitted, err = loadPreparingJournal(root)
		if operationalErr := controlInspectionOperationalError(err); operationalErr != nil {
			return "", "", operationalErr
		}
		if err != nil || !admitted {
			return ControlStateInvalid, "", nil
		}
	}
	if plan.RootID != rootID {
		return ControlStateInvalid, "", nil
	}
	if err := validateActiveState(root, plan); err != nil {
		if operationalErr := controlInspectionOperationalError(err); operationalErr != nil {
			return "", "", operationalErr
		}
		return ControlStateInvalid, "", nil
	}
	committed, committedErr := markerExists(root, committedMarker)
	rolledBack, rolledBackErr := markerExists(root, rolledBackMarker)
	if operationalErr := controlInspectionOperationalError(errors.Join(committedErr, rolledBackErr)); operationalErr != nil {
		return "", "", operationalErr
	}
	if committedErr != nil || rolledBackErr != nil || (committed && rolledBack) {
		return ControlStateInvalid, "", nil
	}
	selected, selectedExists, err := readRecoveryAction(root)
	if operationalErr := controlInspectionOperationalError(err); operationalErr != nil {
		return "", "", operationalErr
	}
	if err != nil || (selectedExists && selected.TransactionID != plan.TransactionID) {
		return ControlStateInvalid, "", nil
	}
	return ControlStateRecoverable, plan.TransactionID, nil
}

func terminalControlState(root *os.Root, terminal terminalControlIdentity) (string, error) {
	path := ControlDirectory + "/" + terminal.Entry.Name()
	if !terminal.Retired {
		children, err := admitTerminalCompaction(root, path, nil)
		if err != nil {
			return ControlStateInvalid, err
		}
		if len(children) > 1 {
			return ControlStateRecoverable, nil
		}
		return ControlStateClean, nil
	}
	children, err := transactionEntries(root, path)
	if err != nil {
		return ControlStateInvalid, err
	}
	if len(children) == 0 {
		return ControlStateClean, nil
	}
	if len(children) != 1 || children[0].Name() != terminalReceiptName {
		return ControlStateInvalid, nil
	}
	receipt, err := loadTerminalReceipt(root, path)
	if err != nil {
		return ControlStateInvalid, err
	}
	if receipt.TransactionID != terminal.TransactionID || receipt.State != terminal.State {
		return ControlStateInvalid, nil
	}
	return ControlStateClean, nil
}

func controlInspectionOperationalError(err error) error {
	if errors.Is(err, ErrReadCleanup) || errors.Is(err, rootpath.ErrTraversalCleanup) {
		return err
	}
	return nil
}
