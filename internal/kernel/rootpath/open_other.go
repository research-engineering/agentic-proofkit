//go:build !darwin && !linux

package rootpath

import (
	"fmt"
	"os"
)

// OpenRegularFile cannot provide no-follow traversal on unsupported platforms.
func OpenRegularFile(*os.Root, string) (*os.File, error) {
	return nil, fmt.Errorf("root file traversal requires darwin or linux")
}

// OpenExactRegularFile reports that descriptor-relative traversal is not
// available outside the package's supported runtime platforms.
func OpenExactRegularFile(root *os.Root, relativePath string) (*os.File, error) {
	file, _, err := OpenObservedExactRegularFile(root, relativePath)
	return file, err
}

// OpenObservedExactRegularFile cannot admit a witness on unsupported platforms.
func OpenObservedExactRegularFile(*os.Root, string) (*os.File, RouteObservation, error) {
	return nil, RouteObservation{}, fmt.Errorf("exact root file traversal requires darwin or linux")
}
