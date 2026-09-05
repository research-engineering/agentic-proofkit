//go:build !darwin && !linux

package rootpath

import (
	"fmt"
	"os"
)

// OpenExactRegularFile reports that descriptor-relative traversal is not
// available outside the package's supported runtime platforms.
func OpenExactRegularFile(*os.Root, string) (*os.File, error) {
	return nil, fmt.Errorf("exact root file traversal requires darwin or linux")
}
