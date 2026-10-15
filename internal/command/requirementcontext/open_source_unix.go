//go:build darwin || linux

package requirementcontext

import (
	"os"
	"syscall"
)

// Keep Root's confinement, but do not wait for a FIFO writer before the
// caller inspects the opened handle's kind and identity.
func openCatalogSourceFile(root *os.Root, path string) (*os.File, error) {
	return root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
