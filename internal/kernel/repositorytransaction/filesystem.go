package repositorytransaction

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

const activeDirectory = ControlDirectory + "/active"

func openRepository(rootPath string) (*os.Root, string, error) {
	if strings.TrimSpace(rootPath) == "" {
		return nil, "", fmt.Errorf("repository root must be explicit")
	}
	absolute, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, "", fmt.Errorf("resolve repository root")
	}
	routeInfo, err := os.Lstat(absolute)
	if err != nil {
		return nil, "", fmt.Errorf("inspect repository root")
	}
	if routeInfo.Mode()&os.ModeSymlink != 0 || !routeInfo.IsDir() {
		return nil, "", fmt.Errorf("repository root must be a non-symlink directory")
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, "", fmt.Errorf("open repository root")
	}
	handleInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(routeInfo, handleInfo) {
		root.Close()
		return nil, "", fmt.Errorf("repository root changed during admission")
	}
	identity, err := platformFileIdentity(handleInfo)
	if err != nil {
		root.Close()
		return nil, "", err
	}
	return root, digest.SHA256TextRef(filepath.Clean(absolute) + "\x00" + identity), nil
}

func inspectParentDirectories(root *os.Root, directory string) ([]string, error) {
	if directory == "." || directory == "" {
		return nil, nil
	}
	components := strings.Split(directory, "/")
	missing := []string{}
	current := ""
	ancestorMissing := false
	for _, component := range components {
		if current == "" {
			current = component
		} else {
			current += "/" + component
		}
		if ancestorMissing {
			missing = append(missing, current)
			continue
		}
		info, err := root.Lstat(filepath.FromSlash(current))
		if errors.Is(err, fs.ErrNotExist) {
			ancestorMissing = true
			missing = append(missing, current)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect repository transaction parent")
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("repository transaction path traverses a symlink or non-directory")
		}
	}
	return missing, nil
}

func inspectTarget(root *os.Root, relativePath string, maximum int64) (Snapshot, []byte, error) {
	missing, err := inspectParentDirectories(root, path.Dir(relativePath))
	if err != nil {
		return Snapshot{}, nil, err
	}
	if len(missing) > 0 {
		return Snapshot{}, nil, nil
	}
	native := filepath.FromSlash(relativePath)
	routeInfo, err := root.Lstat(native)
	if errors.Is(err, fs.ErrNotExist) {
		return Snapshot{}, nil, nil
	}
	if err != nil {
		return Snapshot{}, nil, fmt.Errorf("inspect repository transaction target")
	}
	if routeInfo.Mode()&os.ModeSymlink != 0 || !routeInfo.Mode().IsRegular() || routeInfo.Mode()&^fs.ModePerm != 0 {
		return Snapshot{}, nil, fmt.Errorf("repository transaction target must be a regular non-symlink file")
	}
	if routeInfo.Size() > maximum {
		return Snapshot{}, nil, fmt.Errorf("repository transaction target exceeds the file byte limit")
	}
	file, err := openNoFollow(root, native)
	if err != nil {
		return Snapshot{}, nil, fmt.Errorf("open repository transaction target")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(routeInfo, opened) {
		return Snapshot{}, nil, fmt.Errorf("repository transaction target changed during admission")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		return Snapshot{}, nil, fmt.Errorf("read repository transaction target")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || after.Size() != int64(len(content)) {
		return Snapshot{}, nil, fmt.Errorf("repository transaction target changed during read")
	}
	current, err := root.Lstat(native)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return Snapshot{}, nil, fmt.Errorf("repository transaction target route changed during read")
	}
	snapshot := snapshotForContent(content, opened.Mode().Perm())
	return snapshot, append([]byte(nil), content...), nil
}

func pathExists(root *os.Root, relativePath string) (bool, error) {
	info, err := root.Lstat(filepath.FromSlash(relativePath))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect repository transaction state")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("repository transaction state must not be a symlink")
	}
	return true, nil
}

func ensureDirectory(root *os.Root, relativePath string, mode fs.FileMode) error {
	current := ""
	for _, component := range strings.Split(relativePath, "/") {
		if current == "" {
			current = component
		} else {
			current += "/" + component
		}
		_, err := root.Lstat(filepath.FromSlash(current))
		if errors.Is(err, fs.ErrNotExist) {
			if err := root.Mkdir(filepath.FromSlash(current), mode); err != nil {
				return fmt.Errorf("create repository transaction directory")
			}
			if err := root.Chmod(filepath.FromSlash(current), mode); err != nil {
				return fmt.Errorf("set repository transaction directory mode")
			}
			if err := syncDirectory(root, path.Dir(current)); err != nil {
				return err
			}
		} else if err != nil {
			return fmt.Errorf("inspect repository transaction directory")
		}
		if err := validatePrivateDirectory(root, current, mode); err != nil {
			return err
		}
	}
	return nil
}

func validatePrivateDirectory(root *os.Root, relativePath string, mode fs.FileMode) error {
	native := filepath.FromSlash(relativePath)
	routeInfo, err := root.Lstat(native)
	if err != nil || routeInfo.Mode()&os.ModeSymlink != 0 || !routeInfo.IsDir() || routeInfo.Mode().Perm() != mode.Perm() || routeInfo.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
		return fmt.Errorf("repository transaction directory is unsafe")
	}
	owned, err := platformOwnedByCurrentUser(routeInfo)
	if err != nil || !owned {
		return fmt.Errorf("repository transaction directory is not privately owned")
	}
	directory, err := root.Open(native)
	if err != nil {
		return fmt.Errorf("open repository transaction directory")
	}
	defer directory.Close()
	handleInfo, err := directory.Stat()
	if err != nil || !os.SameFile(routeInfo, handleInfo) {
		return fmt.Errorf("repository transaction directory changed during admission")
	}
	owned, err = platformOwnedByCurrentUser(handleInfo)
	if err != nil || !owned || handleInfo.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("repository transaction directory ownership changed during admission")
	}
	return nil
}

func controlNamespaceExists(root *os.Root) (bool, error) {
	rootExists, err := pathExists(root, ControlRoot)
	if err != nil || !rootExists {
		return false, err
	}
	if err := validatePrivateDirectory(root, ControlRoot, 0o700); err != nil {
		return false, err
	}
	directoryExists, err := pathExists(root, ControlDirectory)
	if err != nil || !directoryExists {
		return false, err
	}
	if err := validatePrivateDirectory(root, ControlDirectory, 0o700); err != nil {
		return false, err
	}
	return true, nil
}

func syncDirectory(root *os.Root, relativePath string) error {
	if relativePath == "" {
		relativePath = "."
	}
	directory, err := root.Open(filepath.FromSlash(relativePath))
	if err != nil {
		return fmt.Errorf("open repository directory for sync")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync repository directory")
	}
	return nil
}

func writeOwnedFile(root *os.Root, relativePath string, content []byte, mode fs.FileMode) error {
	file, err := root.OpenFile(filepath.FromSlash(relativePath), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create repository transaction file")
	}
	remove := true
	defer func() {
		if remove {
			_ = root.Remove(filepath.FromSlash(relativePath))
		}
	}()
	if _, err := file.Write(content); err != nil {
		file.Close()
		return fmt.Errorf("write repository transaction file")
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return fmt.Errorf("set repository transaction file mode")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync repository transaction file")
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close repository transaction file")
	}
	remove = false
	return syncDirectory(root, path.Dir(relativePath))
}

func readOwnedFile(root *os.Root, relativePath string, maximum int64) ([]byte, error) {
	file, err := openNoFollow(root, filepath.FromSlash(relativePath))
	if err != nil {
		return nil, fmt.Errorf("open repository transaction file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&^fs.ModePerm != 0 || info.Mode().Perm() != 0o600 || info.Size() > maximum {
		return nil, fmt.Errorf("repository transaction file is invalid")
	}
	owned, err := platformOwnedByCurrentUser(info)
	if err != nil || !owned {
		return nil, fmt.Errorf("repository transaction file is not privately owned")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		return nil, fmt.Errorf("read repository transaction file")
	}
	current, err := root.Lstat(filepath.FromSlash(relativePath))
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, current) {
		return nil, fmt.Errorf("repository transaction file route changed")
	}
	return content, nil
}

func publishContent(root *os.Root, plan Plan, operationIndex int, expected Snapshot, content []byte, mode fs.FileMode) error {
	operation := plan.Operations[operationIndex]
	temporaryPath := transactionTemporaryPath(plan.TransactionID, operationIndex, operation.Path)
	if exists, err := pathExists(root, temporaryPath); err != nil {
		return err
	} else if exists {
		info, err := root.Lstat(filepath.FromSlash(temporaryPath))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("repository transaction temporary route is unsafe")
		}
		owned, ownershipErr := platformOwnedByCurrentUser(info)
		if ownershipErr != nil || !owned {
			return fmt.Errorf("repository transaction temporary route is not owned")
		}
		if err := root.Remove(filepath.FromSlash(temporaryPath)); err != nil {
			return fmt.Errorf("remove interrupted repository transaction temporary file")
		}
	}
	if err := writeOwnedFile(root, temporaryPath, content, mode); err != nil {
		return err
	}
	observed, _, err := inspectTarget(root, operation.Path, MaximumFileBytes)
	if err != nil || !equalSnapshot(observed, expected) {
		return fmt.Errorf("repository transaction target changed before publication")
	}
	if err := root.Rename(filepath.FromSlash(temporaryPath), filepath.FromSlash(operation.Path)); err != nil {
		return fmt.Errorf("publish repository transaction target")
	}
	if err := syncDirectory(root, path.Dir(operation.Path)); err != nil {
		return err
	}
	observed, observedContent, err := inspectTarget(root, operation.Path, MaximumFileBytes)
	if err != nil || !equalSnapshot(observed, snapshotForContent(content, mode)) || !bytes.Equal(observedContent, content) {
		return fmt.Errorf("repository transaction target failed after publication verification")
	}
	return nil
}

func removeCreatedTarget(root *os.Root, operation Operation) error {
	observed, _, err := inspectTarget(root, operation.Path, MaximumFileBytes)
	if err != nil || !equalSnapshot(observed, operation.After) {
		return fmt.Errorf("repository transaction target cannot be restored")
	}
	if err := root.Remove(filepath.FromSlash(operation.Path)); err != nil {
		return fmt.Errorf("remove created repository transaction target")
	}
	return syncDirectory(root, path.Dir(operation.Path))
}

func transactionTemporaryPath(transactionID string, index int, targetPath string) string {
	_ = transactionID
	_ = targetPath
	return fmt.Sprintf("%s/publish-%03d.tmp", activeDirectory, index)
}

func modeText(mode fs.FileMode) string {
	if mode == 0 {
		return "0000"
	}
	return fmt.Sprintf("%04o", mode.Perm())
}

func parseMode(value any, context string) (fs.FileMode, error) {
	text, ok := value.(string)
	if !ok || len(text) != 4 || text[0] != '0' {
		return 0, fmt.Errorf("%s is invalid", context)
	}
	parsed, err := strconv.ParseUint(text, 8, 32)
	if err != nil || parsed > 0o777 {
		return 0, fmt.Errorf("%s is invalid", context)
	}
	return fs.FileMode(parsed), nil
}

func intString(value int) string {
	return strconv.Itoa(value)
}

func int64String(value int64) string {
	return strconv.FormatInt(value, 10)
}
