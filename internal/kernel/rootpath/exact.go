// Package rootpath owns exact, platform-portable filesystem route lookup
// beneath an already confined os.Root.
package rootpath

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathidentity"
)

const maximumDirectoryEntries = 16 << 10

var (
	ErrAmbiguousRoute   = errors.New("exact root path has an ambiguous portable filesystem identity")
	ErrRouteChanged     = errors.New("exact root path changed during traversal")
	ErrTraversalCleanup = errors.New("exact root path traversal cleanup failed")
	ErrUnsafeRoute      = errors.New("exact root path traverses a symlink or non-regular entry")
)

// ExactEntryExists reports whether component exists with the exact spelling
// supplied by the caller. A portable-equivalent alias is rejected instead of
// being treated as the canonical route on a case-insensitive filesystem.
func ExactEntryExists(root *os.Root, directory, component string) (bool, error) {
	return exactEntryExistsWithClose(root, directory, component, func(file *os.File) error { return file.Close() })
}

func exactEntryExistsWithClose(root *os.Root, directory, component string, closeFile func(*os.File) error) (bool, error) {
	if root == nil {
		return false, fmt.Errorf("exact root path lookup requires a root")
	}
	if closeFile == nil {
		return false, fmt.Errorf("exact root path lookup requires a closer")
	}
	if directory == "" {
		directory = "."
	}
	handle, err := root.Open(filepath.FromSlash(directory))
	if err != nil {
		return false, fmt.Errorf("open exact root path parent directory")
	}
	_, exists, err := exactDirectoryEntry(handle, component)
	if closeErr := closeFile(handle); closeErr != nil {
		return false, fmt.Errorf("%w: close parent directory", ErrTraversalCleanup)
	}
	return exists, err
}

func exactDirectoryEntry(handle *os.File, component string) (fs.DirEntry, bool, error) {
	wantedKey, err := pathidentity.Key(component)
	if err != nil || filepath.Base(component) != component {
		return nil, false, fmt.Errorf("exact root path component is invalid")
	}
	entries, err := handle.ReadDir(maximumDirectoryEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("read exact root path parent directory")
	}
	if len(entries) > maximumDirectoryEntries {
		return nil, false, fmt.Errorf("exact root path parent directory exceeds its entry limit")
	}
	var exact fs.DirEntry
	for _, entry := range entries {
		entryKey, keyErr := pathidentity.Key(entry.Name())
		if keyErr != nil || entryKey != wantedKey {
			continue
		}
		if entry.Name() != component || exact != nil {
			return nil, false, ErrAmbiguousRoute
		}
		exact = entry
	}
	return exact, exact != nil, nil
}
