package artifactfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
)

const temporaryCollisionLimit = 16

func WriteAtomic(rootPath, relativePath string, content []byte, mode fs.FileMode) error {
	path, err := localPath(relativePath)
	if err != nil {
		return err
	}
	if mode&^0o777 != 0 {
		return fmt.Errorf("artifact file mode is invalid")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open artifact root failed")
	}
	defer root.Close()
	if _, err := admitDirectories(root, filepath.Dir(path), true); err != nil {
		return err
	}
	if err := admitDestination(root, path); err != nil {
		return err
	}
	for attempt := 0; attempt < temporaryCollisionLimit; attempt++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return fmt.Errorf("allocate artifact temporary identity failed")
		}
		temporaryPath := path + "." + hex.EncodeToString(nonce[:]) + ".tmp"
		file, err := root.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("create artifact temporary file failed")
		}
		removeTemporary := true
		defer func() {
			if removeTemporary {
				_ = root.Remove(temporaryPath)
			}
		}()
		if _, err := file.Write(content); err != nil {
			file.Close()
			return fmt.Errorf("write artifact temporary file failed")
		}
		if err := file.Sync(); err != nil {
			file.Close()
			return fmt.Errorf("sync artifact temporary file failed")
		}
		if err := file.Chmod(mode); err != nil {
			file.Close()
			return fmt.Errorf("set artifact file mode failed")
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close artifact temporary file failed")
		}
		if _, err := admitDirectories(root, filepath.Dir(path), false); err != nil {
			return err
		}
		if err := admitDestination(root, path); err != nil {
			return err
		}
		if err := root.Rename(temporaryPath, path); err != nil {
			return fmt.Errorf("publish artifact file failed")
		}
		removeTemporary = false
		return nil
	}
	return fmt.Errorf("artifact temporary collision budget exhausted")
}

func ReadBounded(rootPath, relativePath string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 || maxBytes == math.MaxInt64 {
		return nil, fmt.Errorf("artifact read limit is invalid")
	}
	path, err := localPath(relativePath)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open artifact root failed")
	}
	defer root.Close()
	if _, err := admitDirectories(root, filepath.Dir(path), false); err != nil {
		return nil, err
	}
	file, err := openSource(root, path)
	if err != nil {
		if info, inspectErr := root.Lstat(path); inspectErr == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
			return nil, fmt.Errorf("artifact source must be a regular non-symlink file")
		}
		return nil, fmt.Errorf("open artifact file failed")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("artifact source must be a regular non-symlink file")
	}
	if opened.Size() > maxBytes {
		return nil, fmt.Errorf("artifact file exceeds resource limit")
	}
	current, err := root.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return nil, fmt.Errorf("artifact source changed during admission")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read artifact file failed")
	}
	if int64(len(content)) > maxBytes {
		return nil, fmt.Errorf("artifact file exceeds resource limit")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || after.Size() != int64(len(content)) {
		return nil, fmt.Errorf("artifact source changed during read")
	}
	current, err = root.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return nil, fmt.Errorf("artifact source path changed during read")
	}
	return content, nil
}

func Remove(rootPath, relativePath string) error {
	path, err := localPath(relativePath)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open artifact root failed")
	}
	defer root.Close()
	exists, err := admitDirectories(root, filepath.Dir(path), false)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	info, err := root.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect artifact destination failed")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("artifact destination must be a regular non-symlink file")
	}
	if err := root.Remove(path); err != nil {
		return fmt.Errorf("remove artifact file failed")
	}
	return nil
}

func localPath(relativePath string) (string, error) {
	path := filepath.Clean(filepath.FromSlash(relativePath))
	if path == "." || !filepath.IsLocal(path) || filepath.ToSlash(path) != relativePath {
		return "", fmt.Errorf("artifact path must be normalized and repository-relative")
	}
	return path, nil
}

func admitDirectories(root *os.Root, directory string, create bool) (bool, error) {
	if directory == "." {
		return true, nil
	}
	current := ""
	for _, component := range strings.Split(directory, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := root.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			if !create {
				return false, nil
			}
			if err := root.Mkdir(current, 0o755); err != nil {
				return false, fmt.Errorf("create artifact directory failed")
			}
			info, err = root.Lstat(current)
		}
		if err != nil {
			return false, fmt.Errorf("inspect artifact directory failed")
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return false, fmt.Errorf("artifact path traverses a symlink or non-directory")
		}
	}
	return true, nil
}

func admitDestination(root *os.Root, path string) error {
	info, err := root.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect artifact destination failed")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("artifact destination must be a regular non-symlink file")
	}
	return nil
}
