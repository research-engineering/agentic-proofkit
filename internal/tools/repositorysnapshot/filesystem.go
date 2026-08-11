package repositorysnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func admitEmptyDestination(root, destination string, sourceRoot, destinationRoot *os.Root) error {
	rootResolved, err := resolvedPath(root)
	if err != nil {
		return err
	}
	destinationResolved, err := resolvedPath(destination)
	if err != nil {
		return err
	}
	rootInfo, err := os.Stat(rootResolved)
	if err != nil {
		return fmt.Errorf("stat repository snapshot source root failed")
	}
	rootHandleInfo, err := sourceRoot.Stat(".")
	if err != nil || !os.SameFile(rootInfo, rootHandleInfo) {
		return fmt.Errorf("repository snapshot source root changed during admission")
	}
	destinationInfo, err := os.Stat(destinationResolved)
	if err != nil {
		return fmt.Errorf("stat repository snapshot destination failed")
	}
	destinationHandleInfo, err := destinationRoot.Stat(".")
	if err != nil || !os.SameFile(destinationInfo, destinationHandleInfo) {
		return fmt.Errorf("repository snapshot destination changed during admission")
	}
	for current := destinationResolved; ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err != nil {
			return fmt.Errorf("stat repository snapshot destination ancestor failed")
		}
		if os.SameFile(rootInfo, info) {
			return fmt.Errorf("repository snapshot destination must be outside the source root")
		}
		if parent := filepath.Dir(current); parent == current {
			break
		}
	}
	entries, err := fs.ReadDir(destinationRoot.FS(), ".")
	if err != nil {
		return fmt.Errorf("read repository snapshot destination failed")
	}
	if len(entries) != 0 {
		return fmt.Errorf("repository snapshot destination must be empty")
	}
	return nil
}

func resolvedPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("repository snapshot path resolution failed")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("repository snapshot path resolution failed")
	}
	return filepath.Clean(resolved), nil
}

func digestPaths(ctx context.Context, root string, paths []string) (string, error) {
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return "", fmt.Errorf("open repository snapshot root failed")
	}
	defer rootFS.Close()
	hash := sha256.New()
	totalBytes := int64(0)
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("repository snapshot operation canceled: %w", err)
		}
		normalized, err := normalizedPath(path)
		if err != nil {
			return "", err
		}
		info, content, err := readSourceFile(rootFS, normalized)
		if err != nil {
			return "", err
		}
		totalBytes += int64(len(content))
		if totalBytes > maxSnapshotBytes {
			return "", fmt.Errorf("repository snapshot exceeds total byte limit")
		}
		writeDigestField(hash, []byte(normalized))
		writeDigestField(hash, []byte("regular"))
		writeDigestField(hash, []byte(normalizedMode(info.Mode())))
		writeDigestField(hash, content)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func materializedPaths(ctx context.Context, root string) ([]string, error) {
	paths := []string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk materialized repository snapshot failed")
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("repository snapshot operation canceled: %w", err)
		}
		if path == root || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect materialized repository snapshot entry failed")
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("materialized repository snapshot contains non-regular file")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("relativize materialized repository snapshot entry failed")
		}
		normalized, err := normalizedPath(filepath.ToSlash(relative))
		if err != nil {
			return err
		}
		paths = append(paths, normalized)
		if len(paths) > maxSnapshotFiles {
			return fmt.Errorf("materialized repository snapshot exceeds file-count limit")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

func readSourceFile(root *os.Root, path string) (fs.FileInfo, []byte, error) {
	localPath := filepath.FromSlash(path)
	info, err := root.Lstat(localPath)
	if err != nil {
		return nil, nil, fmt.Errorf("repository snapshot source entry lstat failed")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("repository snapshot source entry symlinks are not admitted")
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("repository snapshot source entry non-regular files are not admitted")
	}
	if info.Size() > maxSourceFileBytes {
		return nil, nil, fmt.Errorf("repository snapshot source entry exceeds resource limit")
	}
	file, err := root.Open(localPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open repository snapshot source entry failed")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("repository snapshot source entry changed during admission")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxSourceFileBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read repository snapshot source entry failed")
	}
	if int64(len(content)) > maxSourceFileBytes {
		return nil, nil, fmt.Errorf("repository snapshot source entry exceeds resource limit")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || after.Size() != int64(len(content)) {
		return nil, nil, fmt.Errorf("repository snapshot source entry changed while being read")
	}
	return opened, content, nil
}

func normalizedPath(path string) (string, error) {
	normalized := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if normalized == "." || filepath.IsAbs(filepath.FromSlash(path)) || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", fmt.Errorf("snapshot path must be normalized and repository-relative")
	}
	if path != normalized {
		return "", fmt.Errorf("snapshot path is not normalized")
	}
	return normalized, nil
}

func normalizedMode(mode fs.FileMode) string {
	return fmt.Sprintf("%04o", mode.Perm())
}

func writeDigestField(hash interface{ Write([]byte) (int, error) }, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write(value)
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
