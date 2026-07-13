package retainedevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const ManifestPath = "retained-evidence-checksums.sha256"

var evidencePaths = []string{
	"attestations/github-artifact-attestations.json",
	"release/github-release.json",
}

func EvidencePaths() []string {
	return append([]string(nil), evidencePaths...)
}

func Build(artifactRoot string) ([]byte, error) {
	root, err := os.OpenRoot(artifactRoot)
	if err != nil {
		return nil, fmt.Errorf("open retained evidence root: %w", err)
	}
	defer root.Close()

	if err := requireExactAttestationSet(root); err != nil {
		return nil, err
	}
	paths := EvidencePaths()
	sort.Strings(paths)
	lines := make([]string, 0, len(paths))
	for _, path := range paths {
		content, err := readRegularFile(root, path)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(content)
		lines = append(lines, hex.EncodeToString(sum[:])+"  "+path)
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func Write(artifactRoot string) error {
	content, err := Build(artifactRoot)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(artifactRoot)
	if err != nil {
		return fmt.Errorf("open retained evidence root: %w", err)
	}
	defer root.Close()
	if info, err := root.Lstat(ManifestPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("retained evidence manifest must not be a symlink")
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect retained evidence manifest: %w", err)
	}
	if err := root.WriteFile(ManifestPath, content, 0o644); err != nil {
		return fmt.Errorf("write retained evidence manifest: %w", err)
	}
	return nil
}

func Verify(artifactRoot string) error {
	expected, err := Build(artifactRoot)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(artifactRoot)
	if err != nil {
		return fmt.Errorf("open retained evidence root: %w", err)
	}
	defer root.Close()
	actual, err := readRegularFile(root, ManifestPath)
	if err != nil {
		return err
	}
	if string(actual) != string(expected) {
		return fmt.Errorf("retained evidence manifest does not match artifact topology")
	}
	return nil
}

func requireExactAttestationSet(root *os.Root) error {
	directory, err := root.Open("attestations")
	if err != nil {
		return fmt.Errorf("open retained attestation directory: %w", err)
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("read retained attestation directory: %w", err)
	}
	expectedName := filepath.Base(evidencePaths[0])
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		actual = append(actual, entry.Name())
		if entry.Name() != expectedName || !entry.Type().IsRegular() {
			sort.Strings(actual)
			return fmt.Errorf("retained attestation file set must contain only regular file %s, got %v", expectedName, actual)
		}
	}
	sort.Strings(actual)
	expected := []string{expectedName}
	if len(actual) != len(expected) || actual[0] != expected[0] {
		return fmt.Errorf("retained attestation file set must be exactly %v, got %v", expected, actual)
	}
	return nil
}

func readRegularFile(root *os.Root, path string) ([]byte, error) {
	current := ""
	parts := strings.Split(filepath.ToSlash(path), "/")
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("retained evidence path is not canonical: %s", path)
		}
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("inspect retained evidence path %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("retained evidence path must not contain symlinks: %s", path)
		}
		if index < len(parts)-1 && !info.IsDir() {
			return nil, fmt.Errorf("retained evidence parent must be a directory: %s", path)
		}
		if index == len(parts)-1 && !info.Mode().IsRegular() {
			return nil, fmt.Errorf("retained evidence must be a regular file: %s", path)
		}
	}
	content, err := root.ReadFile(filepath.FromSlash(path))
	if err != nil {
		return nil, fmt.Errorf("read retained evidence %s: %w", path, err)
	}
	return content, nil
}
