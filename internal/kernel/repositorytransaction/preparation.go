package repositorytransaction

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const preparationResidueDirectory = ControlRoot + "/transaction-residue"

const (
	faultBeforePreparationMkdir       failurePoint = "before_preparation_mkdir"
	faultAfterResidueParent           failurePoint = "after_residue_parent"
	faultAfterPreparationMkdir        failurePoint = "after_preparation_mkdir"
	faultAfterPreparationFileCreate   failurePoint = "after_preparation_file_create"
	faultAfterPreparationPartialWrite failurePoint = "after_preparation_partial_write"
	faultAfterPreparationFullWrite    failurePoint = "after_preparation_full_write"
	faultAfterPreparationFileSync     failurePoint = "after_preparation_file_sync"
	faultAfterPreparationJournal      failurePoint = "after_preparation_journal"
	faultBeforePreparationPublish     failurePoint = "before_preparation_publish"
	faultAfterPreparationPublish      failurePoint = "after_preparation_publish"
)

// The caller holds the exclusive transaction lock. No failure here authorizes
// deletion: unpublished evidence is retained, published evidence owns recovery.
func (runtime engine) prepareJournal(ctx context.Context, root *os.Root, lock *transactionLock, plan Plan) (published bool, err error) {
	if err := validateActivePlan(plan); err != nil {
		return false, err
	}
	content, err := stablejson.Marshal(journalValue(plan))
	if err != nil {
		return false, fmt.Errorf("encode repository transaction journal")
	}
	if len(content) > MaximumJournalBytes {
		return false, fmt.Errorf("repository transaction journal exceeds the byte limit")
	}
	rootInfo, err := root.Stat(".")
	if err != nil {
		return false, fmt.Errorf("inspect repository preparation root")
	}
	controlInfo, err := root.Lstat(filepath.FromSlash(ControlRoot))
	if err != nil {
		return false, fmt.Errorf("inspect repository preparation control root")
	}
	lockedInfo, err := lock.directory.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect repository preparation lock")
	}
	routes := map[string]os.FileInfo{ControlRoot: controlInfo, ControlDirectory: lockedInfo}
	verifyRoutes := func() error {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("repository transaction preparation cancelled: %w", err)
		}
		currentRoot, err := os.Lstat(root.Name())
		if err != nil || currentRoot.Mode()&os.ModeSymlink != 0 || !os.SameFile(rootInfo, currentRoot) {
			return ErrControlStateChanged
		}
		for name, pinned := range routes {
			if err := validatePrivateDirectory(root, name, 0o700); err != nil {
				return err
			}
			current, err := root.Lstat(filepath.FromSlash(name))
			if err != nil || !os.SameFile(pinned, current) {
				return ErrControlStateChanged
			}
			if name != ControlRoot {
				same, err := platformSameFilesystem(lockedInfo, current)
				if err != nil || !same {
					return fmt.Errorf("repository transaction preparation requires the same filesystem")
				}
			}
		}
		if exists, err := pathExists(root, activeDirectory); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("repository transaction active state already exists")
		}
		return nil
	}
	if err := verifyRoutes(); err != nil {
		return false, err
	}
	if err := runtime.callFault(faultBeforePreparationMkdir, -1); err != nil {
		return false, err
	}
	if err := ensureDirectory(root, preparationResidueDirectory, 0o700); err != nil {
		return false, err
	}
	residueInfo, err := root.Lstat(filepath.FromSlash(preparationResidueDirectory))
	if err != nil {
		return false, fmt.Errorf("inspect repository preparation residue parent")
	}
	routes[preparationResidueDirectory] = residueInfo
	if err := runtime.callFault(faultAfterResidueParent, -1); err != nil {
		return false, err
	}
	if err := verifyRoutes(); err != nil {
		return false, err
	}
	preparation, err := createPreparationDirectory(root, rand.Reader)
	if err != nil {
		return false, err
	}
	preparationInfo, err := root.Lstat(filepath.FromSlash(preparation))
	if err != nil {
		return false, fmt.Errorf("inspect repository preparation directory")
	}
	routes[preparation] = preparationInfo
	if err := runtime.callFault(faultAfterPreparationMkdir, -1); err != nil {
		return false, err
	}
	if err := verifyRoutes(); err != nil {
		return false, err
	}
	if err := writeOwnedFileWithRetention(root, preparation+"/journal.tmp", content, 0o600, true, runtime.fault); err != nil {
		return false, err
	}
	if err := root.Rename(filepath.FromSlash(preparation+"/journal.tmp"), filepath.FromSlash(preparation+"/journal.json")); err != nil {
		return false, fmt.Errorf("publish repository preparation journal")
	}
	if err := syncDirectory(root, preparation); err != nil {
		return false, err
	}
	if err := runtime.callFault(faultAfterPreparationJournal, -1); err != nil {
		return false, err
	}
	if err := runtime.callFault(faultBeforePreparationPublish, -1); err != nil {
		return false, err
	}
	if err := verifyRoutes(); err != nil {
		return false, err
	}
	observed, err := readOwnedFile(root, preparation+"/journal.json", MaximumJournalBytes)
	if err != nil || !bytes.Equal(content, observed) {
		return false, fmt.Errorf("repository preparation journal differs from the admitted plan")
	}
	if err := verifyRoutes(); err != nil {
		return false, err
	}
	if err := root.Rename(filepath.FromSlash(preparation), filepath.FromSlash(activeDirectory)); err != nil {
		return false, fmt.Errorf("publish repository transaction preparation")
	}
	published = true
	if err := runtime.callFault(faultAfterPreparationPublish, -1); err != nil {
		return published, err
	}
	syncParent := runtime.preparationParentSync
	if syncParent == nil {
		syncParent = syncDirectory
	}
	// Try both parents even when the first sync fails. Publication cannot be undone.
	sourceErr := syncParent(root, preparationResidueDirectory)
	destinationErr := syncParent(root, ControlDirectory)
	return published, errors.Join(sourceErr, destinationErr, ctx.Err())
}

func createPreparationDirectory(root *os.Root, entropy io.Reader) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		var nonce [16]byte
		if _, err := io.ReadFull(entropy, nonce[:]); err != nil {
			return "", fmt.Errorf("create repository preparation nonce")
		}
		name := preparationResidueDirectory + "/preparing-" + hex.EncodeToString(nonce[:])
		if err := root.Mkdir(filepath.FromSlash(name), 0o700); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return "", fmt.Errorf("create repository preparation directory")
		}
		if err := root.Chmod(filepath.FromSlash(name), 0o700); err != nil {
			return "", fmt.Errorf("set repository preparation directory mode")
		}
		if err := validatePrivateDirectory(root, name, 0o700); err != nil {
			return "", err
		}
		if err := syncDirectory(root, preparationResidueDirectory); err != nil {
			return "", err
		}
		return name, nil
	}
	return "", fmt.Errorf("repository preparation attempt collision limit reached")
}
