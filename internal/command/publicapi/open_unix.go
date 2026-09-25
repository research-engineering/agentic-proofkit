//go:build darwin || linux

package publicapi

import (
	"os"

	"golang.org/x/sys/unix"
)

// Keep Root's confined symlink traversal, but do not wait for a FIFO writer
// before the caller can inspect the opened handle's kind and identity.
func openScanFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK, 0)
}
