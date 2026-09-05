//go:build darwin || linux

package rootpath

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

type traversalHook func(componentIndex int)

type traversalOperations struct {
	closeFD   func(int) error
	closeFile func(*os.File) error
}

func nativeTraversalOperations() traversalOperations {
	return traversalOperations{
		closeFD:   unix.Close,
		closeFile: func(file *os.File) error { return file.Close() },
	}
}

// OpenExactRegularFile opens a repository-relative regular file without
// following a symlink in any route component.
func OpenExactRegularFile(root *os.Root, relativePath string) (*os.File, error) {
	return openExactRegularFile(root, relativePath, nil)
}

func openExactRegularFile(root *os.Root, relativePath string, hook traversalHook) (*os.File, error) {
	return openExactRegularFileWithOperations(root, relativePath, hook, nativeTraversalOperations())
}

func openExactRegularFileWithOperations(root *os.Root, relativePath string, hook traversalHook, operations traversalOperations) (*os.File, error) {
	if root == nil || relativePath == "" || path.IsAbs(relativePath) || path.Clean(relativePath) != relativePath {
		return nil, fmt.Errorf("exact root file route is invalid")
	}
	if operations.closeFD == nil || operations.closeFile == nil {
		return nil, fmt.Errorf("exact root file traversal operations are incomplete")
	}
	components := strings.Split(relativePath, "/")
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, fmt.Errorf("exact root file route is invalid")
		}
	}

	current, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open exact root file base")
	}
	for index, component := range components {
		_, exists, err := exactDirectoryEntry(current, component)
		if err != nil {
			if closeErr := closeTraversalFile(operations, current); closeErr != nil {
				return nil, closeErr
			}
			return nil, err
		}
		if !exists {
			if closeErr := closeTraversalFile(operations, current); closeErr != nil {
				return nil, closeErr
			}
			return nil, fs.ErrNotExist
		}
		var expected unix.Stat_t
		if err := unix.Fstatat(int(current.Fd()), component, &expected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if closeErr := closeTraversalFile(operations, current); closeErr != nil {
				return nil, closeErr
			}
			if errors.Is(err, unix.ENOENT) {
				return nil, ErrRouteChanged
			}
			return nil, fmt.Errorf("inspect exact root file route")
		}
		last := index == len(components)-1
		kind := expected.Mode & unix.S_IFMT
		if kind == unix.S_IFLNK || (!last && kind != unix.S_IFDIR) || (last && kind != unix.S_IFREG) {
			if closeErr := closeTraversalFile(operations, current); closeErr != nil {
				return nil, closeErr
			}
			return nil, ErrUnsafeRoute
		}
		if hook != nil {
			hook(index)
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if !last {
			flags |= unix.O_DIRECTORY
		}
		fd, openErr := unix.Openat(int(current.Fd()), component, flags, 0)
		if openErr != nil {
			if closeErr := closeTraversalFile(operations, current); closeErr != nil {
				return nil, closeErr
			}
			if errors.Is(openErr, unix.ENOENT) || errors.Is(openErr, unix.ELOOP) || errors.Is(openErr, unix.ENOTDIR) {
				return nil, ErrRouteChanged
			}
			return nil, fmt.Errorf("open exact root file route")
		}
		var observed unix.Stat_t
		if statErr := unix.Fstat(fd, &observed); statErr != nil || expected.Dev != observed.Dev || expected.Ino != observed.Ino {
			if closeErr := errors.Join(closeTraversalFD(operations, fd), closeTraversalFile(operations, current)); closeErr != nil {
				return nil, closeErr
			}
			return nil, ErrRouteChanged
		}
		next := os.NewFile(uintptr(fd), "exact-root-entry")
		if next == nil {
			if closeErr := errors.Join(closeTraversalFD(operations, fd), closeTraversalFile(operations, current)); closeErr != nil {
				return nil, closeErr
			}
			return nil, fmt.Errorf("adopt exact root file descriptor")
		}
		if closeErr := closeTraversalFile(operations, current); closeErr != nil {
			return nil, errors.Join(closeErr, closeTraversalFile(operations, next))
		}
		current = next
	}
	return current, nil
}

func closeTraversalFile(operations traversalOperations, file *os.File) error {
	if err := operations.closeFile(file); err != nil {
		return fmt.Errorf("%w: file descriptor", ErrTraversalCleanup)
	}
	return nil
}

func closeTraversalFD(operations traversalOperations, descriptor int) error {
	if err := operations.closeFD(descriptor); err != nil {
		return fmt.Errorf("%w: raw descriptor", ErrTraversalCleanup)
	}
	return nil
}
