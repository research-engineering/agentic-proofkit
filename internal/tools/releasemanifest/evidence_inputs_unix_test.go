//go:build darwin || linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
)

func TestEvidenceInputsRejectUnsafeRoutesWithoutBlocking(t *testing.T) {
	readers := []struct {
		name    string
		missing error
		read    func(root, path string) error
	}{
		{"pack", artifactfile.ErrMissing, func(root, path string) error { _, err := readPackRecords(root, path); return err }},
		{"npm-registry", nil, func(root, path string) error { _, err := optionalNPMRegistrySet(root, path); return err }},
		{"python-candidate", nil, func(root, path string) error { _, err := optionalPythonPackageSet(root, path); return err }},
		{"pypi-registry", nil, func(root, path string) error { _, err := optionalPyPIRegistrySet(root, path); return err }},
		{"publication-mode", nil, func(root, path string) error { _, err := optionalPublicationMode(root, path, "npm"); return err }},
		{"installed-evidence", nil, func(root, path string) error {
			_, err := optionalRegistryInstallEvidence(root, filepath.Dir(path), nil)
			return err
		}},
	}
	for _, reader := range readers {
		t.Run(reader.name, func(t *testing.T) {
			root := t.TempDir()
			const path = "evidence/audit-signatures.txt"
			if err := os.Mkdir(filepath.Join(root, "evidence"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := reader.read(root, path); !errors.Is(err, reader.missing) {
				t.Fatalf("missing operand: %v", err)
			}
			target := filepath.Join(root, path)
			if err := os.Symlink("missing", target); err != nil {
				t.Fatal(err)
			}
			if err := reader.read(root, path); err == nil || errors.Is(err, artifactfile.ErrMissing) {
				t.Fatalf("dangling symlink was not refused as unsafe: %v", err)
			}
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(target, 0o600); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { result <- reader.read(root, path) }()
			select {
			case err := <-result:
				if err == nil || !strings.Contains(err.Error(), "regular non-symlink file") {
					t.Fatalf("FIFO refusal = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("evidence admission blocked on a FIFO")
			}
		})
	}
}

func TestPublicationModeBoundsBytesBeforeTrim(t *testing.T) {
	root := t.TempDir()
	const name = "publication-mode.txt"
	for _, length := range []int{64, 65} {
		const mode = "existing_byte_match"
		writeFile(t, filepath.Join(root, name), mode+strings.Repeat(" ", length-len(mode)))
		value, err := optionalPublicationMode(root, name, "npm")
		if length == 64 && (err != nil || value != mode) {
			t.Fatalf("bounded mode = %q, %v", value, err)
		}
		if length == 65 && (err == nil || !strings.Contains(err.Error(), "resource limit")) {
			t.Fatalf("oversized mode refusal = %v", err)
		}
	}
}
