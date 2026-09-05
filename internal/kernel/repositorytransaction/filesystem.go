package repositorytransaction

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/rootpath"
)

const (
	activeDirectory = ControlDirectory + "/active"
)

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

func exactRouteExists(root *os.Root, relativePath string) (bool, error) {
	current := ""
	components := strings.Split(relativePath, "/")
	for index, component := range components {
		parent := current
		if parent == "" {
			parent = "."
		}
		exists, err := rootpath.ExactEntryExists(root, parent, component)
		if err != nil || !exists {
			return false, err
		}
		if current == "" {
			current = component
		} else {
			current += "/" + component
		}
		if index < len(components)-1 {
			info, err := root.Lstat(filepath.FromSlash(current))
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return false, fmt.Errorf("repository transaction path traverses a symlink or non-directory")
			}
		}
	}
	return true, nil
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
		parent := path.Dir(current)
		exists, err := rootpath.ExactEntryExists(root, parent, component)
		if err != nil {
			return nil, err
		}
		if !exists {
			ancestorMissing = true
			missing = append(missing, current)
			continue
		}
		info, err := root.Lstat(filepath.FromSlash(current))
		if err != nil {
			return nil, fmt.Errorf("inspect repository transaction parent")
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("repository transaction path traverses a symlink or non-directory")
		}
	}
	return missing, nil
}

func inspectTarget(root *os.Root, relativePath string, maximum int64) (snapshot Snapshot, content []byte, returnErr error) {
	missing, err := inspectParentDirectories(root, path.Dir(relativePath))
	if err != nil {
		return Snapshot{}, nil, err
	}
	if len(missing) > 0 {
		return Snapshot{}, nil, nil
	}
	targetExists, err := rootpath.ExactEntryExists(root, path.Dir(relativePath), path.Base(relativePath))
	if err != nil {
		return Snapshot{}, nil, err
	}
	if !targetExists {
		return Snapshot{}, nil, nil
	}
	native := filepath.FromSlash(relativePath)
	routeInfo, err := root.Lstat(native)
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
	defer func() {
		if closeErr := closeReadResource(file, "transaction target"); closeErr != nil {
			snapshot = Snapshot{}
			content = nil
			returnErr = closeErr
		}
	}()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(routeInfo, opened) {
		return Snapshot{}, nil, fmt.Errorf("repository transaction target changed during admission")
	}
	content, err = io.ReadAll(io.LimitReader(file, maximum+1))
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
	snapshot = snapshotForContent(content, opened.Mode().Perm())
	return snapshot, append([]byte(nil), content...), nil
}

func pathExists(root *os.Root, relativePath string) (bool, error) {
	exact, err := exactRouteExists(root, relativePath)
	if err != nil || !exact {
		return false, err
	}
	info, err := root.Lstat(filepath.FromSlash(relativePath))
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
		parent := path.Dir(current)
		exists, err := rootpath.ExactEntryExists(root, parent, component)
		if err != nil {
			return err
		}
		if !exists {
			if err := root.Mkdir(filepath.FromSlash(current), mode); err != nil {
				return fmt.Errorf("create repository transaction directory")
			}
			if err := root.Chmod(filepath.FromSlash(current), mode); err != nil {
				return fmt.Errorf("set repository transaction directory mode")
			}
			if err := syncDirectory(root, path.Dir(current)); err != nil {
				return err
			}
		}
		if err := validatePrivateDirectory(root, current, mode); err != nil {
			return err
		}
	}
	return nil
}

func validatePrivateDirectory(root *os.Root, relativePath string, mode fs.FileMode) (returnErr error) {
	exact, err := exactRouteExists(root, relativePath)
	if err != nil {
		return err
	}
	if !exact {
		return fmt.Errorf("repository transaction directory route is invalid")
	}
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
	defer func() {
		if closeErr := closeReadResource(directory, "private transaction directory"); closeErr != nil {
			returnErr = closeErr
		}
	}()
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

func syncDirectory(root *os.Root, relativePath string) (returnErr error) {
	if relativePath == "" {
		relativePath = "."
	}
	directory, err := root.Open(filepath.FromSlash(relativePath))
	if err != nil {
		return fmt.Errorf("open repository directory for sync")
	}
	defer func() {
		if closeErr := closeReadResource(directory, "synced transaction directory"); closeErr != nil {
			returnErr = closeErr
		}
	}()
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

func writeAtomicOwnedFile(root *os.Root, relativePath, temporaryPath string, content []byte, mode fs.FileMode) error {
	if exists, err := pathExists(root, relativePath); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("repository transaction file already exists")
	}
	if err := discardOwnedTemporaryFile(root, temporaryPath); err != nil {
		return err
	}
	if err := writeOwnedFile(root, temporaryPath, content, mode); err != nil {
		return err
	}
	if err := root.Rename(filepath.FromSlash(temporaryPath), filepath.FromSlash(relativePath)); err != nil {
		return fmt.Errorf("publish repository transaction file")
	}
	return syncDirectory(root, path.Dir(relativePath))
}

func discardOwnedTemporaryFile(root *os.Root, relativePath string) error {
	exists, err := exactRouteExists(root, relativePath)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	info, err := root.Lstat(filepath.FromSlash(relativePath))
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode()&^fs.ModePerm != 0 {
		return fmt.Errorf("repository transaction temporary file is unsafe")
	}
	owned, ownershipErr := platformOwnedByCurrentUser(info)
	if ownershipErr != nil || !owned {
		return fmt.Errorf("repository transaction temporary file is not owned")
	}
	if err := root.Remove(filepath.FromSlash(relativePath)); err != nil {
		return fmt.Errorf("remove interrupted repository transaction temporary file")
	}
	return syncDirectory(root, path.Dir(relativePath))
}

func readOwnedFile(root *os.Root, relativePath string, maximum int64) (content []byte, returnErr error) {
	exists, err := exactRouteExists(root, relativePath)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("repository transaction file route is invalid")
	}
	file, err := openNoFollow(root, filepath.FromSlash(relativePath))
	if err != nil {
		return nil, fmt.Errorf("open repository transaction file")
	}
	defer func() {
		if closeErr := closeReadResource(file, "private transaction file"); closeErr != nil {
			content = nil
			returnErr = closeErr
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&^fs.ModePerm != 0 || info.Mode().Perm() != 0o600 || info.Size() > maximum {
		return nil, fmt.Errorf("repository transaction file is invalid")
	}
	owned, err := platformOwnedByCurrentUser(info)
	if err != nil || !owned {
		return nil, fmt.Errorf("repository transaction file is not privately owned")
	}
	content, err = io.ReadAll(io.LimitReader(file, maximum+1))
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
	return removeExactTarget(root, operation.Path, operation.After)
}

func removeExactTarget(root *os.Root, targetPath string, expected Snapshot) error {
	observed, _, err := inspectTarget(root, targetPath, MaximumFileBytes)
	if err != nil || !expected.Exists || !equalSnapshot(observed, expected) {
		return fmt.Errorf("repository transaction target cannot be restored")
	}
	if err := root.Remove(filepath.FromSlash(targetPath)); err != nil {
		return fmt.Errorf("remove repository transaction target")
	}
	if err := syncDirectory(root, path.Dir(targetPath)); err != nil {
		return err
	}
	observed, _, err = inspectTarget(root, targetPath, MaximumFileBytes)
	if err != nil || observed.Exists {
		return fmt.Errorf("repository transaction target is not absent after removal")
	}
	return nil
}

func verifyDeletionFilesystem(root *os.Root, targetPath string) error {
	if _, err := inspectParentDirectories(root, path.Dir(targetPath)); err != nil {
		return err
	}
	missing, err := inspectParentDirectories(root, activeDirectory)
	if err != nil {
		return err
	}
	stagingAncestor := activeDirectory
	if len(missing) > 0 {
		stagingAncestor = path.Dir(missing[0])
	}
	staging, err := root.Lstat(filepath.FromSlash(stagingAncestor))
	if err != nil || !staging.IsDir() {
		return fmt.Errorf("repository transaction staging filesystem is unavailable")
	}
	parent, err := root.Lstat(filepath.FromSlash(path.Dir(targetPath)))
	if err != nil || !parent.IsDir() {
		return fmt.Errorf("repository transaction deletion parent is unavailable")
	}
	same, err := platformSameFilesystem(staging, parent)
	if err != nil || !same {
		return fmt.Errorf("repository transaction deletion requires same-filesystem rollback")
	}
	return nil
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
