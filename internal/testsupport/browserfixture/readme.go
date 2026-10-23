package browserfixture

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// readmeProject is a committed, materialized synthetic project: four delivery
// requirements of example.dispatch with their bindings, test inventory and
// routing manifest. The README scene serves it through the project view path.
//
//go:embed testdata/readme-project
var readmeProject embed.FS

const readmeProjectRoot = "testdata/readme-project"

// MaterializeReadmeProject writes the committed project files into an empty
// directory so the project view path inspects real repository files.
func MaterializeReadmeProject(directory string) error {
	return fs.WalkDir(readmeProject, readmeProjectRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(readmeProjectRoot, filepath.FromSlash(path))
		if err != nil {
			return err
		}
		target := filepath.Join(directory, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("README project fixture must contain only regular files")
		}
		content, err := readmeProject.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, content, 0o644)
	})
}

// StaticCompactProof exercises the compact proof contract through the static
// proof renderer, alongside the structured binding of StaticProof.
func StaticCompactProof() (map[string]any, error) {
	input, err := CoverageInput("compact")
	if err != nil {
		return nil, err
	}
	return input["compactProofContract"].(map[string]any), nil
}
