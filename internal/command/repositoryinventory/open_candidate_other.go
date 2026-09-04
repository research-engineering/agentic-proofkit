//go:build !(darwin || linux)

package repositoryinventory

import (
	"fmt"
	"os"
)

func openCandidateFile(root *os.Root, path string) (*os.File, error) {
	return nil, fmt.Errorf("repository inventory scanning is unsupported on this platform")
}
