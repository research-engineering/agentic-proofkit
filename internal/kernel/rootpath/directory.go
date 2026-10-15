package rootpath

import (
	"os"
	"syscall"
)

// OpenDirectoryRoot opens a caller-selected repository root, following an
// initial symlink as os.OpenRoot does. os.OpenRoot opens without O_NONBLOCK,
// so a FIFO would wait for a writer before its directory check; this preflight
// rejects static non-directories first. It does not make acquisition atomic
// under concurrent replacement of name.
func OpenDirectoryRoot(name string) (*os.Root, error) {
	info, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ENOTDIR}
	}
	return os.OpenRoot(name)
}
