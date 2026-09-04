//go:build !darwin && !linux

package artifactfile

import (
	"fmt"
	"os"
)

func openSource(_ *os.Root, _ string) (*os.File, error) {
	return nil, fmt.Errorf("nonblocking no-follow artifact reads are unsupported on this platform")
}
