package projectstatus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

var errSnapshotChanged = errors.New("project status snapshot changed during inspection")

type fileState string

const (
	fileMissing fileState = "missing"
	fileInvalid fileState = "invalid"
	fileRead    fileState = "read"
)

type fileObservation struct {
	content []byte
	digest  string
	state   fileState
}

type readBudget struct {
	remaining int64
}

func readProjectFile(ctx context.Context, lease *repositorytransaction.InspectionLease, relativePath string, budget *readBudget) (fileObservation, error) {
	return readProjectFileWithHook(ctx, lease, relativePath, budget, nil)
}

func readProjectFileWithHook(ctx context.Context, lease *repositorytransaction.InspectionLease, relativePath string, budget *readBudget, beforeRouteReopen func()) (observation fileObservation, returnErr error) {
	if err := ctx.Err(); err != nil {
		return fileObservation{}, err
	}
	file, err := lease.OpenExactRegularFile(relativePath)
	if errors.Is(err, fs.ErrNotExist) {
		return fileObservation{state: fileMissing}, nil
	}
	if errors.Is(err, repositorytransaction.ErrUnsafeInspectionRoute) {
		return fileObservation{state: fileInvalid}, nil
	}
	if errors.Is(err, repositorytransaction.ErrInspectionRouteChanged) {
		return fileObservation{}, errSnapshotChanged
	}
	if err != nil {
		return fileObservation{}, fmt.Errorf("open project status record route")
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			observation = fileObservation{}
			returnErr = fmt.Errorf("close project status record: %w", closeErr)
		}
	}()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode()&^fs.ModePerm != 0 {
		return fileObservation{}, fmt.Errorf("inspect project status record")
	}
	if opened.Size() < 0 || opened.Size() > MaximumFileBytes || opened.Size() > budget.remaining {
		return fileObservation{state: fileInvalid}, nil
	}
	content, err := io.ReadAll(io.LimitReader(file, opened.Size()+1))
	if err != nil {
		return fileObservation{}, fmt.Errorf("read project status record")
	}
	if int64(len(content)) != opened.Size() {
		return fileObservation{}, errSnapshotChanged
	}
	afterHandle, err := file.Stat()
	if err != nil || !os.SameFile(opened, afterHandle) || opened.Size() != afterHandle.Size() || !opened.ModTime().Equal(afterHandle.ModTime()) {
		return fileObservation{}, errSnapshotChanged
	}
	if beforeRouteReopen != nil {
		beforeRouteReopen()
	}
	current, err := lease.OpenExactRegularFile(relativePath)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, repositorytransaction.ErrUnsafeInspectionRoute) || errors.Is(err, repositorytransaction.ErrInspectionRouteChanged) {
		return fileObservation{}, errSnapshotChanged
	}
	if err != nil {
		return fileObservation{}, fmt.Errorf("reopen project status record route")
	}
	if err := verifyReopenedProjectFile(current, opened, int64(len(content))); err != nil {
		return fileObservation{}, err
	}
	budget.remaining -= int64(len(content))
	return fileObservation{content: append([]byte{}, content...), digest: digest.SHA256BytesRef(content), state: fileRead}, nil
}

func verifyReopenedProjectFile(current repositorytransaction.InspectionFile, opened fs.FileInfo, contentSize int64) error {
	currentInfo, statErr := current.Stat()
	closeErr := current.Close()
	if closeErr != nil {
		return fmt.Errorf("close rechecked project status record: %w", closeErr)
	}
	if statErr != nil || !os.SameFile(opened, currentInfo) || currentInfo.Size() != contentSize {
		return errSnapshotChanged
	}
	return nil
}
