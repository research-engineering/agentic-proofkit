package artifactfile

import (
	"fmt"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/rootpath"
)

// ResetDirectory recreates one owned directory in an exclusive workspace.
// Static route admission precedes all effects; I/O failures do not roll back.
func ResetDirectory(rootPath, relativePath string) error {
	path, err := localPath(relativePath)
	if err != nil {
		return err
	}
	root, err := rootpath.OpenDirectoryRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open artifact root failed")
	}
	defer root.Close()

	// Include the target in the non-creating preflight. Once an ancestor is
	// missing, no further component can exist on this static route.
	if _, err := admitDirectories(root, path, false); err != nil {
		return err
	}
	if _, err := admitDirectories(root, filepath.Dir(path), true); err != nil {
		return err
	}
	if err := root.RemoveAll(path); err != nil {
		return fmt.Errorf("reset artifact directory failed")
	}
	if err := root.Mkdir(path, 0o755); err != nil {
		return fmt.Errorf("create artifact directory failed")
	}
	return nil
}
