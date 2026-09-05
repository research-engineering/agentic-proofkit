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
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathidentity"
)

const maximumDirectoryEntries = 16 << 10

var (
	ErrAmbiguousRoute   = errors.New("exact root path has an ambiguous portable filesystem identity")
	ErrRouteChanged     = errors.New("exact root path changed during traversal")
	ErrTraversalCleanup = errors.New("exact root path traversal cleanup failed")
	ErrUnsafeRoute      = errors.New("exact root path traverses a symlink or non-regular entry")
)

type routeTerminal uint8

const (
	routeIncomplete routeTerminal = iota
	routeRegular
	routeMissing
	routeUnsafe
)

type routeComponent struct {
	device uint64
	inode  uint64
	mode   uint32
}

// RouteObservation is an immutable, process-local traversal witness. Its
// private components include the base directory but exclude directory size
// and timestamps, which can change through unrelated sibling writes.
type RouteObservation struct {
	route      string
	components []routeComponent
	terminal   routeTerminal
	position   int
}

// Equal compares complete observations only; a zero or incomplete witness
// never supplies evidence of stability, even when compared with itself.
func (observation RouteObservation) Equal(other RouteObservation) bool {
	return observation.complete() && other.complete() &&
		observation.route == other.route && observation.terminal == other.terminal &&
		observation.position == other.position && slices.Equal(observation.components, other.components)
}

func (observation RouteObservation) complete() bool {
	if observation.route == "" || observation.position < 0 {
		return false
	}
	last := strings.Count(observation.route, "/")
	if observation.position > last {
		return false
	}
	switch observation.terminal {
	case routeMissing:
		return len(observation.components) == observation.position+1
	case routeUnsafe:
		return len(observation.components) == observation.position+2
	case routeRegular:
		return observation.position == last && len(observation.components) == last+2
	default:
		return false
	}
}

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
