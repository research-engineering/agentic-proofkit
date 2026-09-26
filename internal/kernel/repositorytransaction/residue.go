package repositorytransaction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/rootpath"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	PreparationResidueAbsent      = "absent"
	PreparationResidueEligible    = "eligible"
	PreparationResidueQuarantined = "quarantined"
)

var (
	ErrResidueObservationInvalid = errors.New("preparation residue observation is invalid")
	ErrResidueIneligible         = errors.New("preparation residue is unsafe, recognized or unsupported")
	ErrResidueAbsent             = errors.New("preparation residue is absent")
	ErrResidueDestinationPresent = errors.New("preparation residue quarantine destination is already present")
	ErrResidueFilesystem         = errors.New("preparation residue quarantine requires the same filesystem")
	ErrResidueOperation          = errors.New("preparation residue operation failed")
	ErrResidueOutcomeUnverified  = errors.New("preparation residue quarantine outcome is unverified")
)

// PreparationResidueObservation exposes no identity inferred from journal bytes.
// ObservationID is empty for absent; eligible IDs bind the version-1 native token.
type PreparationResidueObservation struct {
	State         string
	ObservationID string
}

// PreparationResidueRelocation acknowledges only an observed relocation, never
// rollback, target state, historical effects or a transaction terminal result.
type PreparationResidueRelocation struct {
	State         string
	ObservationID string
}

// InspectPreparationResidue performs no writes and never competes with a writer
// by classifying its preparation before acquiring the cooperative read lease.
func InspectPreparationResidue(ctx context.Context, explicitRoot string) (PreparationResidueObservation, error) {
	return inspectPreparationResidue(ctx, explicitRoot, nativeResidueOperations())
}

// QuarantinePreparationResidue retains the entire observed directory at a fixed
// destination. A retry refuses an occupied destination before reading active.
func QuarantinePreparationResidue(ctx context.Context, explicitRoot, expectedObservation string) (PreparationResidueRelocation, error) {
	return quarantinePreparationResidue(ctx, explicitRoot, expectedObservation, nativeResidueOperations())
}

// Dependencies are private, per-call test barriers; production has no fault mode.
type residueOperations struct {
	openLease      func(context.Context, string, transactionLockMode) (*InspectionLease, error)
	closeLease     func(*InspectionLease) error
	openFile       func(*InspectionLease, string) (InspectionFile, error)
	syncParent     func(*os.Root, string) error
	sameFilesystem func(os.FileInfo, os.FileInfo) (bool, error)
	barrier        func(string) error
}

func nativeResidueOperations() residueOperations {
	return residueOperations{
		openLease: openInspectionLease, closeLease: (*InspectionLease).Close,
		openFile: (*InspectionLease).OpenExactRegularFile, syncParent: syncDirectory,
		sameFilesystem: platformSameFilesystem, barrier: func(string) error { return nil },
	}
}

// Do not propagate diagnostic text from caller bytes, paths, or injected I/O.
// Opaque legacy-owner failures remain operation failures, not shape decisions.
func residueError(err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		classified := make([]error, 0, len(causes))
		for _, cause := range causes {
			classified = append(classified, residueError(cause))
		}
		return errors.Join(classified...)
	}
	var causes []error
	for _, known := range []error{
		ErrReadCleanup, rootpath.ErrTraversalCleanup, context.Canceled, context.DeadlineExceeded,
		ErrBusy, ErrControlStateChanged, ErrResidueObservationInvalid, ErrResidueIneligible,
		ErrResidueAbsent, ErrResidueDestinationPresent, ErrResidueFilesystem, ErrResidueOperation,
	} {
		if errors.Is(err, known) {
			causes = append(causes, known)
		}
	}
	if errors.Is(err, rootpath.ErrAmbiguousRoute) || errors.Is(err, ErrUnsafeInspectionRoute) || errors.Is(err, rootpath.ErrUnsafeRoute) {
		causes = append(causes, ErrResidueIneligible)
	}
	if errors.Is(err, ErrInspectionRouteChanged) || errors.Is(err, rootpath.ErrRouteChanged) {
		causes = append(causes, ErrControlStateChanged)
	}
	if len(causes) == 0 {
		return ErrResidueOperation
	}
	return errors.Join(causes...)
}

type residueUnverifiedError struct{ cause error }

func (err *residueUnverifiedError) Error() string { return ErrResidueOutcomeUnverified.Error() }
func (err *residueUnverifiedError) Unwrap() []error {
	return []error{ErrResidueOutcomeUnverified, err.cause}
}

func inspectPreparationResidue(ctx context.Context, rootPath string, operations residueOperations) (result PreparationResidueObservation, returnErr error) {
	defer func() {
		returnErr = errors.Join(residueError(returnErr), ctx.Err())
		if returnErr != nil {
			result = PreparationResidueObservation{}
		}
	}()
	lease, err := operations.openLease(ctx, rootPath, transactionReadLock)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, operations.closeLease(lease)) }()
	return observePreparationResidue(ctx, lease, activeDirectory, operations)
}

func quarantinePreparationResidue(ctx context.Context, rootPath, expected string, operations residueOperations) (result PreparationResidueRelocation, returnErr error) {
	published := false
	defer func() {
		returnErr = errors.Join(residueError(returnErr), ctx.Err())
		if returnErr != nil {
			result = PreparationResidueRelocation{}
			if published {
				returnErr = &residueUnverifiedError{cause: returnErr}
			}
		}
	}()
	canonical, err := admit.SHA256Ref(expected, "preparation residue observation")
	if err != nil || canonical != expected {
		return result, ErrResidueObservationInvalid
	}
	lease, err := operations.openLease(ctx, rootPath, transactionWriteLock)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, operations.closeLease(lease)) }()
	destination := preparationResidueDirectory + "/quarantined-" + strings.TrimPrefix(expected, "sha256:")
	// This check must precede even an absent/invalid/new active observation.
	if err := residueDestinationAbsent(lease.root, destination); err != nil {
		return result, err
	}
	before, err := observePreparationResidue(ctx, lease, activeDirectory, operations)
	if err != nil {
		return result, err
	}
	if before.State == PreparationResidueAbsent {
		return result, ErrResidueAbsent
	}
	if before.ObservationID != expected {
		return result, ErrControlStateChanged
	}
	if err := ensureDirectory(lease.root, preparationResidueDirectory, 0o700); err != nil {
		return result, err
	}
	parent, err := residueDirectory(lease.root, preparationResidueDirectory)
	if err != nil {
		return result, err
	}
	if err := operations.barrier("parent-pinned"); err != nil {
		return result, err
	}
	current, err := observePreparationResidue(ctx, lease, activeDirectory, operations)
	if err != nil {
		return result, err
	}
	if current != before {
		return result, ErrControlStateChanged
	}
	if err := verifyResidueParent(lease, parent, operations); err != nil {
		return result, err
	}
	if err := residueDestinationAbsent(lease.root, destination); err != nil {
		return result, err
	}
	if err := errors.Join(lease.VerifyRootIdentity(), ctx.Err()); err != nil {
		return result, err
	}
	if err := lease.root.Rename(filepath.FromSlash(activeDirectory), filepath.FromSlash(destination)); err != nil {
		return result, ErrResidueOperation
	}
	published = true
	if err := operations.barrier("published"); err != nil {
		return result, err
	}
	// Attempt both syncs; nothing after publication authorizes reversing the move.
	sourceErr := operations.syncParent(lease.root, ControlDirectory)
	destinationErr := operations.syncParent(lease.root, preparationResidueDirectory)
	if err := errors.Join(sourceErr, destinationErr, ctx.Err()); err != nil {
		return result, err
	}
	if err := verifyResidueParent(lease, parent, operations); err != nil {
		return result, err
	}
	moved, err := observePreparationResidue(ctx, lease, destination, operations)
	if err != nil {
		return result, err
	}
	if moved != before {
		return result, ErrControlStateChanged
	}
	if err := verifyResidueParent(lease, parent, operations); err != nil {
		return result, err
	}
	return PreparationResidueRelocation{State: PreparationResidueQuarantined, ObservationID: expected}, nil
}

func residueDestinationAbsent(root *os.Root, destination string) error {
	exists, err := exactRouteExists(root, preparationResidueDirectory)
	if err != nil || !exists {
		return err
	}
	if _, err := residueDirectory(root, preparationResidueDirectory); err != nil {
		return err
	}
	exists, err = exactRouteExists(root, destination)
	if err != nil {
		return err
	}
	if exists {
		return ErrResidueDestinationPresent
	}
	return nil
}

func verifyResidueParent(lease *InspectionLease, expected os.FileInfo, operations residueOperations) error {
	current, err := residueDirectory(lease.root, preparationResidueDirectory)
	if err != nil {
		return err
	}
	if !os.SameFile(expected, current) {
		return ErrControlStateChanged
	}
	locked, err := lease.lock.directory.Stat()
	if err != nil {
		return ErrResidueOperation
	}
	active, err := lease.root.Lstat(filepath.FromSlash(activeDirectory))
	if errors.Is(err, os.ErrNotExist) {
		active = locked // Post-publication: the moved identity is checked separately.
	} else if err != nil {
		return ErrResidueOperation
	}
	for _, info := range []os.FileInfo{locked, active} {
		same, err := operations.sameFilesystem(info, current)
		if err != nil {
			return err
		}
		if !same {
			return ErrResidueFilesystem
		}
	}
	return lease.VerifyRootIdentity()
}

func residueDirectory(root *os.Root, name string) (os.FileInfo, error) {
	exists, err := exactRouteExists(root, name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrControlStateChanged
	}
	info, err := root.Lstat(filepath.FromSlash(name))
	if err != nil {
		return nil, ErrResidueOperation
	}
	if _, err := residueNodeValue(info, path.Base(name), true); err != nil {
		return nil, err
	}
	return info, nil
}

func verifyResidueDirectory(root *os.Root, name string, expected os.FileInfo) error {
	current, err := residueDirectory(root, name)
	if err != nil {
		return err
	}
	if !os.SameFile(expected, current) {
		return ErrControlStateChanged
	}
	return nil
}

func residueNodeValue(info os.FileInfo, name string, directory bool) (map[string]any, error) {
	wantMode := os.FileMode(0o600)
	kind := "regular"
	if directory {
		wantMode, kind = os.ModeDir|0o700, "directory"
	}
	if info.Mode() != wantMode {
		return nil, ErrResidueIneligible
	}
	owned, err := platformOwnedByCurrentUser(info)
	if err != nil {
		return nil, err
	}
	if !owned {
		return nil, ErrResidueIneligible
	}
	identity, err := platformFileIdentity(info)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"name": name, "kind": kind, "identity": identity,
		"mode":    json.Number(int64String(int64(info.Mode()))),
		"ownerId": json.Number(intString(os.Geteuid())),
	}, nil
}

func observePreparationResidue(ctx context.Context, lease *InspectionLease, source string, operations residueOperations) (PreparationResidueObservation, error) {
	before, err := capturePreparationResidue(ctx, lease, source, operations)
	if err != nil {
		return PreparationResidueObservation{}, err
	}
	if err := operations.barrier("reobserve"); err != nil {
		return PreparationResidueObservation{}, err
	}
	after, err := capturePreparationResidue(ctx, lease, source, operations)
	if err != nil {
		return PreparationResidueObservation{}, err
	}
	if before != after {
		return PreparationResidueObservation{}, ErrControlStateChanged
	}
	if err := errors.Join(lease.VerifyRootIdentity(), ctx.Err()); err != nil {
		return PreparationResidueObservation{}, err
	}
	return after, nil
}

func capturePreparationResidue(ctx context.Context, lease *InspectionLease, source string, operations residueOperations) (PreparationResidueObservation, error) {
	if err := errors.Join(lease.VerifyRootIdentity(), ctx.Err()); err != nil {
		return PreparationResidueObservation{}, err
	}
	if !lease.controlNamespace {
		return PreparationResidueObservation{State: PreparationResidueAbsent}, nil
	}
	value := map[string]any{
		"observationKind": "proofkit.preparation-residue-observation", "schemaVersion": json.Number("1"),
		"rootId": lease.rootID, "effectiveUserId": json.Number(intString(os.Geteuid())),
	}
	for _, name := range []string{ControlRoot, ControlDirectory} {
		info, err := residueDirectory(lease.root, name)
		if err != nil {
			return PreparationResidueObservation{}, err
		}
		value[name], err = residueNodeValue(info, path.Base(name), true)
		if err != nil {
			return PreparationResidueObservation{}, err
		}
	}
	entries, err := readInspectionEntries(lease.root, ControlDirectory, 2)
	if err != nil {
		return PreparationResidueObservation{}, residueShapeError(err)
	}
	terminal, found, err := findTerminalControlEntry(entries)
	if err != nil {
		return PreparationResidueObservation{}, ErrResidueIneligible
	}
	value["terminal"] = nil
	if found {
		value["terminal"], err = captureResidueTerminal(ctx, lease, terminal, operations)
		if err != nil {
			return PreparationResidueObservation{}, err
		}
	}
	exists, err := exactRouteExists(lease.root, activeDirectory)
	if err != nil {
		return PreparationResidueObservation{}, err
	}
	if source != activeDirectory && exists {
		return PreparationResidueObservation{}, ErrControlStateChanged
	}
	if source == activeDirectory && !exists {
		return PreparationResidueObservation{State: PreparationResidueAbsent}, nil
	}
	info, err := residueDirectory(lease.root, source)
	if err != nil {
		return PreparationResidueObservation{}, err
	}
	node, err := residueNodeValue(info, "active", true)
	if err != nil {
		return PreparationResidueObservation{}, err
	}
	children, err := readInspectionEntries(lease.root, source, 1)
	if err != nil {
		return PreparationResidueObservation{}, residueShapeError(err)
	}
	node["journal"] = nil
	if len(children) != 0 {
		if children[0].Name() != "journal.tmp" {
			return PreparationResidueObservation{}, ErrResidueIneligible
		}
		fileValue, content, err := readResidueFile(ctx, lease, source+"/journal.tmp", MaximumJournalBytes, operations)
		if err != nil {
			return PreparationResidueObservation{}, err
		}
		if raw, err := admission.DecodeJSON(bytes.NewReader(content), MaximumJournalBytes); err == nil {
			// Even noncanonical serialization or a foreign root cannot turn a
			// fully admitted known plan into identity-unknown residue.
			if _, err := admitJournal(raw); err == nil {
				return PreparationResidueObservation{}, ErrResidueIneligible
			}
		}
		node["journal"] = fileValue
	}
	if err := verifyResidueDirectory(lease.root, source, info); err != nil {
		return PreparationResidueObservation{}, err
	}
	value["active"] = node
	token, err := digest.StableJSONSHA256Ref(value)
	if err != nil {
		return PreparationResidueObservation{}, err
	}
	return PreparationResidueObservation{State: PreparationResidueEligible, ObservationID: token}, nil
}

func residueShapeError(err error) error {
	if errors.Is(err, errControlObservationShape) || errors.Is(err, errControlObservationBound) {
		return ErrResidueIneligible
	}
	return err
}

// The clean terminal grammar is exactly receipt-only, or an empty retired
// directory. Admit the captured bytes with the terminal owner's pure validator;
// never collapse its separate filesystem reads into a semantic rejection.
func captureResidueTerminal(ctx context.Context, lease *InspectionLease, terminal terminalControlIdentity, operations residueOperations) (value map[string]any, returnErr error) {
	name := ControlDirectory + "/" + terminal.Entry.Name()
	info, err := residueDirectory(lease.root, name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr == nil {
			returnErr = verifyResidueDirectory(lease.root, name, info)
			if returnErr != nil {
				value = nil
			}
		}
	}()
	value, err = residueNodeValue(info, terminal.Entry.Name(), true)
	if err != nil {
		return nil, err
	}
	children, err := readInspectionEntries(lease.root, name, 1)
	if err != nil {
		return nil, residueShapeError(err)
	}
	value["receipt"] = nil
	if terminal.Retired && len(children) == 0 {
		return value, nil
	}
	if len(children) != 1 || children[0].Name() != terminalReceiptName {
		return nil, ErrResidueIneligible
	}
	fileValue, content, err := readResidueFile(ctx, lease, name+"/"+terminalReceiptName, maximumTerminalReceiptBytes, operations)
	if err != nil {
		return nil, err
	}
	raw, err := admission.DecodeJSON(bytes.NewReader(content), maximumTerminalReceiptBytes)
	if err != nil {
		return nil, ErrResidueIneligible
	}
	receipt, err := admitTerminalReceipt(raw)
	if err != nil || receipt.TransactionID != terminal.TransactionID || receipt.State != terminal.State {
		return nil, ErrResidueIneligible
	}
	canonical, err := stablejson.Marshal(terminalReceiptValue(receipt))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, content) {
		return nil, ErrResidueIneligible
	}
	value["receipt"] = fileValue
	return value, nil
}

func readResidueFile(ctx context.Context, lease *InspectionLease, name string, maximum int64, operations residueOperations) (value map[string]any, content []byte, returnErr error) {
	file, err := operations.openFile(lease, name)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err := closeReadResource(file, "preparation residue file"); err != nil {
			value, content, returnErr = nil, nil, errors.Join(returnErr, err)
		}
	}()
	before, err := file.Stat()
	if err != nil {
		return nil, nil, ErrResidueOperation
	}
	value, err = residueNodeValue(before, path.Base(name), false)
	if err != nil {
		return nil, nil, err
	}
	if before.Size() < 0 || before.Size() > maximum {
		return nil, nil, ErrResidueIneligible
	}
	limited := io.LimitReader(file, maximum+1)
	buffer := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		count, err := limited.Read(buffer)
		content = append(content, buffer[:count]...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, ErrResidueOperation
		}
	}
	after, err := file.Stat()
	if err != nil {
		return nil, nil, ErrResidueOperation
	}
	if !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || after.Size() != int64(len(content)) || !before.ModTime().Equal(after.ModTime()) {
		return nil, nil, ErrControlStateChanged
	}
	current, err := lease.root.Lstat(filepath.FromSlash(name))
	if err != nil {
		return nil, nil, ErrResidueOperation
	}
	if !os.SameFile(before, current) || before.Mode() != current.Mode() || before.Size() != current.Size() || !before.ModTime().Equal(current.ModTime()) {
		return nil, nil, ErrControlStateChanged
	}
	exact, err := exactRouteExists(lease.root, name)
	if err != nil {
		return nil, nil, err
	}
	if !exact {
		return nil, nil, ErrControlStateChanged
	}
	if _, err := residueNodeValue(current, path.Base(name), false); err != nil {
		return nil, nil, err
	}
	value["size"] = json.Number(int64String(int64(len(content))))
	value["contentId"] = digest.SHA256BytesRef(content)
	return value, content, nil
}
