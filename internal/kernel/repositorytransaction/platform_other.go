//go:build !darwin && !linux

package repositorytransaction

import (
	"fmt"
	"os"
)

func platformFileIdentity(os.FileInfo) (string, error) {
	return "", fmt.Errorf("repository transactions require darwin or linux")
}

func platformOwnedByCurrentUser(os.FileInfo) (bool, error) {
	return false, fmt.Errorf("repository transactions require darwin or linux")
}

func openNoFollow(*os.Root, string) (*os.File, error) {
	return nil, fmt.Errorf("repository transactions require darwin or linux")
}

func lockDirectory(*os.File) error {
	return fmt.Errorf("repository transactions require darwin or linux")
}

func unlockDirectory(*os.File) error {
	return fmt.Errorf("repository transactions require darwin or linux")
}
