package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGoBuilderOutputBoundaryOrdinaryAndRetiredCleanup(t *testing.T) {
	for _, route := range []string{"ordinary", "artifacts ancestor alias", "legacy platform alias"} {
		t.Run(route, func(t *testing.T) {
			t.Chdir(t.TempDir())
			t.Setenv("PATH", "")
			writeGoBoundaryManifest(t, nil)
			writeGoBoundaryFile(t, "dist/old-output", "old dist")
			outside := t.TempDir()
			sentinel := filepath.Join(outside, "platform", "sentinel")
			writeGoBoundaryFile(t, sentinel, "outside platform")
			var alias string
			switch route {
			case "artifacts ancestor alias":
				alias = "artifacts"
				if err := os.Symlink(outside, alias); err != nil {
					t.Fatal(err)
				}
			case "legacy platform alias":
				if err := os.Mkdir("artifacts", 0o755); err != nil {
					t.Fatal(err)
				}
				alias = "artifacts/platform"
				if err := os.Symlink(filepath.Dir(sentinel), alias); err != nil {
					t.Fatal(err)
				}
			}

			err := run([]string{"current"})
			var child *exec.Error
			if !errors.As(err, &child) || child.Name != "go" || !errors.Is(err, exec.ErrNotFound) {
				t.Fatalf("ordinary output route must reach unavailable compiler, got %v", err)
			}
			if _, err := os.Lstat("dist/old-output"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("admitted dist was not reset: %v", err)
			}
			assertGoBoundaryFile(t, sentinel, "outside platform")
			if alias != "" {
				info, err := os.Lstat(alias)
				if err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("retired cleanup changed unrelated alias: %v", err)
				}
			}
		})
	}
}

func TestGoBuilderOutputBoundaryRefusesDistBeforeChild(t *testing.T) {
	for _, shape := range []string{"symlink", "non-directory"} {
		t.Run(shape, func(t *testing.T) {
			t.Chdir(t.TempDir())
			t.Setenv("PATH", "")
			writeGoBoundaryManifest(t, nil)
			outside := t.TempDir()
			sentinel := filepath.Join(outside, "sentinel")
			writeGoBoundaryFile(t, sentinel, "outside target")
			if shape == "symlink" {
				if err := os.Symlink(outside, "dist"); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Link(sentinel, "dist"); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat("dist")
			if err != nil {
				t.Fatal(err)
			}

			err = run([]string{"current"})
			if err == nil || err.Error() != "artifact path traverses a symlink or non-directory" {
				t.Fatalf("want output preflight refusal, not child failure: %v", err)
			}
			after, err := os.Lstat("dist")
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("preflight replaced dist: %v", err)
			}
			assertGoBoundaryFile(t, sentinel, "outside target")
		})
	}
}

func TestGoBuilderOutputBoundaryMetadataPrecedesReset(t *testing.T) {
	const synthetic = "api_key=synthetic_boundary_dummy_0123456789"
	for _, tc := range []struct {
		name, field, want string
		value             any
	}{
		{"invalid version", "version", "root package version must be an exact semantic version", "not-a-version"},
		{"unsafe description", "description", "package metadata description contains a secret-like value", synthetic},
		{"unsafe URL", "repository.url", "package metadata repository.url contains a secret-like value", "https://example.test/?" + synthetic},
		{"null description", "description", "package metadata description must be a string", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			t.Setenv("PATH", "")
			writeGoBoundaryManifest(t, func(manifest map[string]any) {
				if tc.field == "repository.url" {
					manifest["repository"].(map[string]any)["url"] = tc.value
				} else {
					manifest[tc.field] = tc.value
				}
			})
			writeGoBoundaryFile(t, "dist/old-output", "old dist")

			err := run([]string{"current"})
			if err == nil || err.Error() != tc.want {
				t.Fatalf("want fixed metadata refusal %q, got %v", tc.want, err)
			}
			assertGoBoundaryFile(t, "dist/old-output", "old dist")
		})
	}
}

func writeGoBoundaryManifest(t *testing.T, patch func(map[string]any)) {
	t.Helper()
	manifest := map[string]any{
		"version":    "1.2.3",
		"repository": map[string]any{"url": "https://example.test/repo"},
	}
	if patch != nil {
		patch(manifest)
	}
	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeGoBoundaryFile(t, "package.json", string(content))
}

func writeGoBoundaryFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertGoBoundaryFile(t *testing.T, path, want string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil || string(content) != want {
		t.Fatalf("preserved file %s = %q, %v; want %q", path, content, err, want)
	}
}
