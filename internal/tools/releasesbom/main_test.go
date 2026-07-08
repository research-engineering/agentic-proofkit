package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

func TestReadPackageJSONRejectsAmbiguousJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.json")
	if err := os.WriteFile(path, []byte(`{"name":"agentic-proofkit","name":"other","version":"1.2.3","license":"MIT"}`), 0o600); err != nil {
		t.Fatalf("write package manifest: %v", err)
	}

	_, err := readPackageJSON(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("readPackageJSON() error = %v, want duplicate-key rejection", err)
	}
}

func TestReleaseFilePathsRequireReleasePlatformBinarySet(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T)
		want  string
	}{
		{
			name: "missing owner binary",
			setup: func(t *testing.T) {
				writeReleasePlatformBinaries(t, releaseplatform.BinaryPaths()[:len(releaseplatform.BinaryPaths())-1])
			},
			want: "missing release platform binary",
		},
		{
			name: "unmanaged stale binary",
			setup: func(t *testing.T) {
				writeReleasePlatformBinaries(t, releaseplatform.BinaryPaths())
				writeFile(t, filepath.Join("dist", "platform", "freebsd-x64", releaseplatform.BinaryName), "stale")
			},
			want: "unmanaged release platform binary",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			withTempWD(t, func() {
				item.setup(t)

				_, err := releaseFilePaths()
				if err == nil || !strings.Contains(err.Error(), item.want) {
					t.Fatalf("releaseFilePaths() error=%v, want %q", err, item.want)
				}
			})
		})
	}
	t.Run("complete owner set", func(t *testing.T) {
		withTempWD(t, func() {
			writeReleasePlatformBinaries(t, releaseplatform.BinaryPaths())
			paths, err := releaseFilePaths()
			if err != nil {
				t.Fatalf("releaseFilePaths() error=%v", err)
			}
			if len(paths) != len(releaseplatform.BinaryPaths()) {
				t.Fatalf("releaseFilePaths() paths=%v, want owner binary set only", paths)
			}
		})
	})
}

func TestSBOMSerialNumberIsDeterministicCycloneDXURN(t *testing.T) {
	manifest := packageJSON{Name: "@research-engineering/agentic-proofkit", Version: "1.2.3"}
	got := sbomSerialNumber(manifest)
	if !strings.HasPrefix(got, "urn:uuid:") {
		t.Fatalf("sbomSerialNumber()=%q, want urn:uuid prefix", got)
	}
	uuid := strings.TrimPrefix(got, "urn:uuid:")
	if len(uuid) != len("00000000-0000-0000-0000-000000000000") {
		t.Fatalf("sbomSerialNumber()=%q, want RFC 4122 UUID length", got)
	}
	for _, index := range []int{8, 13, 18, 23} {
		if uuid[index] != '-' {
			t.Fatalf("sbomSerialNumber()=%q, want UUID hyphen at %d", got, index)
		}
	}
	if uuid[14] != '5' {
		t.Fatalf("sbomSerialNumber()=%q, want UUID v5 version nibble", got)
	}
	if got != sbomSerialNumber(manifest) {
		t.Fatalf("sbomSerialNumber() must be deterministic")
	}
	changed := sbomSerialNumber(packageJSON{Name: manifest.Name, Version: "1.2.4"})
	if got == changed {
		t.Fatalf("sbomSerialNumber()=%q did not change when package version changed", got)
	}
}

func writeReleasePlatformBinaries(t *testing.T, paths []string) {
	t.Helper()
	for _, path := range paths {
		writeFile(t, path, "binary")
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func withTempWD(t *testing.T, fn func()) {
	t.Helper()
	root := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	}()
	fn()
}
