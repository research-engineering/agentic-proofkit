package repositorytransaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const maximumDirectoryOwnershipBytes = 4096

type directoryOwnership struct {
	Identity      string
	Path          string
	TransactionID string
}

func ensureTargetDirectories(root *os.Root, plan Plan) error {
	for index, directory := range plan.CreatedDirectories {
		record, recorded, err := loadDirectoryOwnership(root, plan, index)
		if err != nil {
			return err
		}
		if recorded {
			identity, exists, err := inspectOwnedTargetDirectory(root, directory)
			if err != nil || !exists || identity != record.Identity {
				return fmt.Errorf("repository target directory ownership changed")
			}
			continue
		}
		if _, exists, err := inspectOwnedTargetDirectory(root, directory); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("repository target directory appeared without transaction ownership")
		}
		if err := root.Mkdir(filepath.FromSlash(directory), 0o755); err != nil {
			return fmt.Errorf("create repository target directory")
		}
		if err := root.Chmod(filepath.FromSlash(directory), 0o755); err != nil {
			return fmt.Errorf("set repository target directory mode")
		}
		identity, exists, err := inspectOwnedTargetDirectory(root, directory)
		if err != nil || !exists {
			return fmt.Errorf("admit created repository target directory")
		}
		if err := syncDirectory(root, path.Dir(directory)); err != nil {
			return err
		}
		record = directoryOwnership{Identity: identity, Path: directory, TransactionID: plan.TransactionID}
		if err := writeDirectoryOwnership(root, index, record); err != nil {
			_ = removeOwnedTargetDirectory(root, directory, identity)
			return err
		}
	}
	return nil
}

func removeCreatedDirectories(root *os.Root, plan Plan) error {
	for index := len(plan.CreatedDirectories) - 1; index >= 0; index-- {
		directory := plan.CreatedDirectories[index]
		record, recorded, err := loadDirectoryOwnership(root, plan, index)
		if err != nil {
			return err
		}
		identity, exists, err := inspectOwnedTargetDirectory(root, directory)
		if err != nil {
			return err
		}
		if !recorded {
			if exists {
				return fmt.Errorf("repository target directory lacks transaction ownership")
			}
			continue
		}
		if !exists {
			continue
		}
		if identity != record.Identity {
			return fmt.Errorf("repository target directory ownership changed")
		}
		if err := removeOwnedTargetDirectory(root, directory, identity); err != nil {
			return err
		}
	}
	return nil
}

func inspectOwnedTargetDirectory(root *os.Root, relativePath string) (string, bool, error) {
	native := filepath.FromSlash(relativePath)
	routeInfo, err := root.Lstat(native)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil || routeInfo.Mode()&os.ModeSymlink != 0 || !routeInfo.IsDir() || routeInfo.Mode().Perm() != 0o755 {
		return "", false, fmt.Errorf("repository target directory is unsafe")
	}
	owned, err := platformOwnedByCurrentUser(routeInfo)
	if err != nil || !owned {
		return "", false, fmt.Errorf("repository target directory is not owned by the current user")
	}
	directory, err := root.Open(native)
	if err != nil {
		return "", false, fmt.Errorf("open repository target directory")
	}
	defer directory.Close()
	handleInfo, err := directory.Stat()
	if err != nil || !os.SameFile(routeInfo, handleInfo) {
		return "", false, fmt.Errorf("repository target directory changed during admission")
	}
	identity, err := platformFileIdentity(handleInfo)
	if err != nil {
		return "", false, err
	}
	current, err := root.Lstat(native)
	if err != nil || !os.SameFile(handleInfo, current) {
		return "", false, fmt.Errorf("repository target directory route changed during admission")
	}
	return identity, true, nil
}

func removeOwnedTargetDirectory(root *os.Root, relativePath, expectedIdentity string) error {
	identity, exists, err := inspectOwnedTargetDirectory(root, relativePath)
	if err != nil || !exists || identity != expectedIdentity {
		return fmt.Errorf("repository target directory cannot be restored")
	}
	if err := root.Remove(filepath.FromSlash(relativePath)); err != nil {
		return fmt.Errorf("repository target directory cannot be restored")
	}
	return syncDirectory(root, path.Dir(relativePath))
}

func writeDirectoryOwnership(root *os.Root, index int, record directoryOwnership) error {
	content, err := stablejson.Marshal(directoryOwnershipValue(record))
	if err != nil || len(content) > maximumDirectoryOwnershipBytes {
		return fmt.Errorf("encode repository target directory ownership")
	}
	return writeOwnedFile(root, directoryOwnershipPath(index), content, 0o600)
}

func loadDirectoryOwnership(root *os.Root, plan Plan, index int) (directoryOwnership, bool, error) {
	relativePath := directoryOwnershipPath(index)
	exists, err := pathExists(root, relativePath)
	if err != nil || !exists {
		return directoryOwnership{}, false, err
	}
	content, err := readOwnedFile(root, relativePath, maximumDirectoryOwnershipBytes)
	if err != nil {
		return directoryOwnership{}, false, err
	}
	raw, err := admission.DecodeJSON(bytes.NewReader(content), maximumDirectoryOwnershipBytes)
	if err != nil {
		return directoryOwnership{}, false, fmt.Errorf("admit repository target directory ownership")
	}
	record, err := admitDirectoryOwnership(raw)
	if err != nil || index >= len(plan.CreatedDirectories) || record.Path != plan.CreatedDirectories[index] || record.TransactionID != plan.TransactionID {
		return directoryOwnership{}, false, fmt.Errorf("repository target directory ownership does not match the transaction")
	}
	canonical, err := stablejson.Marshal(directoryOwnershipValue(record))
	if err != nil || !bytes.Equal(content, canonical) {
		return directoryOwnership{}, false, fmt.Errorf("repository target directory ownership is not canonical")
	}
	return record, true, nil
}

func admitDirectoryOwnership(raw any) (directoryOwnership, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return directoryOwnership{}, fmt.Errorf("repository target directory ownership must be an object")
	}
	if err := admit.KnownKeys(record, []string{"directoryKind", "identity", "path", "schemaVersion", "transactionId"}, "repository target directory ownership"); err != nil {
		return directoryOwnership{}, err
	}
	if record["directoryKind"] != "proofkit.repository-created-directory" || !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return directoryOwnership{}, fmt.Errorf("repository target directory ownership identity is invalid")
	}
	identity, err := admit.NonEmptyText(record["identity"], "repository target directory ownership filesystem identity")
	if err != nil {
		return directoryOwnership{}, err
	}
	directoryPath, err := admit.SafeRepoRelativePath(recordText(record["path"]), "repository target directory ownership path")
	if err != nil {
		return directoryOwnership{}, err
	}
	transactionID, err := admit.SHA256Ref(record["transactionId"], "repository target directory ownership transactionId")
	if err != nil {
		return directoryOwnership{}, err
	}
	return directoryOwnership{Identity: identity, Path: directoryPath, TransactionID: transactionID}, nil
}

func directoryOwnershipValue(record directoryOwnership) map[string]any {
	return map[string]any{
		"directoryKind": "proofkit.repository-created-directory",
		"identity":      record.Identity,
		"path":          record.Path,
		"schemaVersion": json.Number("1"),
		"transactionId": record.TransactionID,
	}
}

func directoryOwnershipPath(index int) string {
	return fmt.Sprintf("%s/directory-%04d.json", activeDirectory, index)
}
