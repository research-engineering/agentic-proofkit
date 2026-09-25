//go:build !darwin && !linux

package publicapi

import (
	"fmt"
	"os"
)

func openScanFile(*os.Root, string) (*os.File, error) {
	return nil, fmt.Errorf("nonblocking public API file admission requires darwin or linux")
}
