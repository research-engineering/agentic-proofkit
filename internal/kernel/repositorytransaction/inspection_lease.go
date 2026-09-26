package repositorytransaction

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/rootpath"
)

// InspectionFile is the read-only capability returned by an inspection lease.
// Callers must close the file before closing the lease; the interface exposes
// no mutation methods.
type InspectionFile interface {
	io.Reader
	io.Closer
	Stat() (fs.FileInfo, error)
}

type inspectionFile struct {
	file *os.File
}

func (file *inspectionFile) Read(buffer []byte) (int, error) {
	if file == nil || file.file == nil {
		return 0, os.ErrClosed
	}
	return file.file.Read(buffer)
}

func (file *inspectionFile) Stat() (fs.FileInfo, error) {
	if file == nil || file.file == nil {
		return nil, os.ErrClosed
	}
	return file.file.Stat()
}

func (file *inspectionFile) Close() error {
	if file == nil || file.file == nil {
		return os.ErrClosed
	}
	underlying := file.file
	file.file = nil
	return underlying.Close()
}

var (
	ErrInspectionRouteChanged = errors.New("repository inspection route changed")
	ErrReadCleanup            = errors.New("repository read cleanup failed")
	ErrUnsafeInspectionRoute  = errors.New("repository inspection route is unsafe")
)

func isReadCleanup(err error) bool {
	return errors.Is(err, ErrReadCleanup) || errors.Is(err, rootpath.ErrTraversalCleanup)
}

func closeReadResource(resource io.Closer, label string) error {
	if err := resource.Close(); err != nil {
		return fmt.Errorf("%w: %s", ErrReadCleanup, label)
	}
	return nil
}

// InspectionLease pins one repository root and, when the transaction control
// namespace exists, holds a shared cooperative lock for the full read.
type InspectionLease struct {
	absolute         string
	controlNamespace bool
	identity         os.FileInfo
	controlIdentity  os.FileInfo
	lock             *transactionLock
	root             *os.Root
	rootID           string
}

func OpenInspectionLease(ctx context.Context, rootPath string) (lease *InspectionLease, returnErr error) {
	return openInspectionLease(ctx, rootPath, transactionReadLock)
}

func openInspectionLease(ctx context.Context, rootPath string, mode transactionLockMode) (lease *InspectionLease, returnErr error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("open repository inspection lease cancelled: %w", err)
	}
	root, rootID, err := openRepository(rootPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			if closeErr := closeReadResource(root, "inspection root admission"); closeErr != nil {
				returnErr = errors.Join(closeErr, ctx.Err())
			}
		}
	}()
	absolute, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("resolve repository inspection root")
	}
	identity, err := root.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("inspect repository inspection root")
	}
	// Bind the control parent as well as the locked directory, so moving the
	// same locked inode into a replacement parent cannot validate the route.
	controlIdentity, controlErr := root.Lstat(filepath.FromSlash(ControlRoot))
	if controlErr != nil && !errors.Is(controlErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect repository transaction control root")
	}
	lock, exists, err := acquireExistingLock(root, mode)
	if err != nil {
		return nil, err
	}
	lease = &InspectionLease{
		absolute: absolute, controlNamespace: exists, identity: identity,
		controlIdentity: controlIdentity, lock: lock, root: root, rootID: rootID,
	}
	if err := errors.Join(lease.VerifyRootIdentity(), ctx.Err()); err != nil {
		if closeErr := lock.releaseChecked(); closeErr != nil {
			return nil, errors.Join(ErrReadCleanup, ctx.Err())
		}
		return nil, err
	}
	return lease, nil
}

// OpenExactRegularFile opens one exact repository-relative regular file
// without exposing the mutation-capable confined root.
func (lease *InspectionLease) OpenExactRegularFile(relativePath string) (InspectionFile, error) {
	file, _, err := lease.OpenObservedExactRegularFile(relativePath)
	return file, err
}

// OpenObservedExactRegularFile projects a read-only file capability and the
// traversal owner's opaque witness, including missing and unsafe terminals.
func (lease *InspectionLease) OpenObservedExactRegularFile(relativePath string) (InspectionFile, rootpath.RouteObservation, error) {
	if lease == nil || lease.root == nil {
		return nil, rootpath.RouteObservation{}, fmt.Errorf("repository inspection lease is closed")
	}
	file, observation, err := rootpath.OpenObservedExactRegularFile(lease.root, relativePath)
	switch {
	case errors.Is(err, rootpath.ErrTraversalCleanup):
		return nil, rootpath.RouteObservation{}, err
	case errors.Is(err, rootpath.ErrRouteChanged):
		return nil, rootpath.RouteObservation{}, ErrInspectionRouteChanged
	case errors.Is(err, rootpath.ErrUnsafeRoute):
		return nil, observation, ErrUnsafeInspectionRoute
	case err == nil:
		return &inspectionFile{file: file}, observation, nil
	default:
		return nil, observation, err
	}
}

func (lease *InspectionLease) VerifyRootIdentity() error {
	if lease == nil || lease.root == nil {
		return fmt.Errorf("repository inspection lease is closed")
	}
	handleInfo, err := lease.root.Stat(".")
	if err != nil || !os.SameFile(lease.identity, handleInfo) {
		return ErrControlStateChanged
	}
	routeInfo, err := os.Lstat(lease.absolute)
	if err != nil || routeInfo.Mode()&os.ModeSymlink != 0 || !routeInfo.IsDir() || !os.SameFile(lease.identity, routeInfo) {
		return ErrControlStateChanged
	}
	exists, err := controlNamespaceExists(lease.root)
	if err != nil {
		return err
	}
	if exists != lease.controlNamespace {
		return ErrControlStateChanged
	}
	if !exists {
		return nil
	}
	parentInfo, err := lease.root.Lstat(filepath.FromSlash(ControlRoot))
	if err != nil || lease.controlIdentity == nil || !os.SameFile(lease.controlIdentity, parentInfo) {
		return ErrControlStateChanged
	}
	lockedInfo, err := lease.lock.directory.Stat()
	if err != nil {
		return ErrControlStateChanged
	}
	controlInfo, err := lease.root.Lstat(filepath.FromSlash(ControlDirectory))
	if err != nil || !os.SameFile(lockedInfo, controlInfo) {
		return ErrControlStateChanged
	}
	return nil
}

func (lease *InspectionLease) InspectControlState(ctx context.Context) (ControlInspection, error) {
	return lease.inspectControlState(ctx, nil)
}

func (lease *InspectionLease) inspectControlState(ctx context.Context, beforeReobserve func()) (ControlInspection, error) {
	if lease == nil || lease.root == nil {
		return ControlInspection{}, fmt.Errorf("repository inspection lease is closed")
	}
	if err := ctx.Err(); err != nil {
		return ControlInspection{}, fmt.Errorf("inspect repository transaction control state cancelled: %w", err)
	}
	if !lease.controlNamespace {
		exists, err := controlNamespaceExists(lease.root)
		if err != nil {
			return ControlInspection{}, err
		}
		if exists {
			return ControlInspection{}, ErrControlStateChanged
		}
		emptyObservationID, err := emptyControlObservationID()
		if err != nil {
			return ControlInspection{}, err
		}
		return newControlInspection(ControlStateClean, "", emptyObservationID)
	}

	before, err := observeControlNamespace(ctx, lease.root)
	if err != nil {
		return ControlInspection{}, err
	}
	state, transactionID, err := classifyControlState(lease.root, lease.rootID, before)
	if err != nil {
		return ControlInspection{}, err
	}
	if err := ctx.Err(); err != nil {
		return ControlInspection{}, fmt.Errorf("inspect repository transaction control state cancelled: %w", err)
	}
	if beforeReobserve != nil {
		beforeReobserve()
	}
	after, err := observeControlNamespace(ctx, lease.root)
	if err != nil {
		return ControlInspection{}, err
	}
	afterState, afterTransactionID, err := classifyControlState(lease.root, lease.rootID, after)
	if err != nil {
		return ControlInspection{}, err
	}
	if before.Digest != after.Digest || state != afterState || transactionID != afterTransactionID {
		return ControlInspection{}, ErrControlStateChanged
	}
	return newControlInspection(state, transactionID, after.Digest)
}

func (lease *InspectionLease) Close() error {
	if lease == nil || lease.root == nil {
		return nil
	}
	lockErr := lease.lock.releaseChecked()
	rootErr := lease.root.Close()
	lease.lock = nil
	lease.root = nil
	if err := errors.Join(lockErr, rootErr); err != nil {
		return fmt.Errorf("%w: inspection lease", ErrReadCleanup)
	}
	return nil
}
