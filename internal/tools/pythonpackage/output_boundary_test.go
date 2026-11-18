package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPythonBuilderOutputBoundaryOrdinaryControl(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PATH", "")
	platform := writePythonBoundaryFixture(t, testPackageManifest("1.2.3"))
	writePythonBoundaryFile(t, "artifacts/pypi/old-output", "old wheel")
	writePythonBoundaryFile(t, "artifacts/unrelated", "unrelated artifact")
	writePythonBoundaryFile(t, "artifacts/pypi/python-packages.json", "old report")

	if err := run([]string{"build-current"}); err != nil {
		t.Fatalf("ordinary build from synthetic binary and sources: %v", err)
	}
	if _, err := os.Lstat("artifacts/pypi/old-output"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ordinary build did not reset old output: %v", err)
	}
	assertPythonBoundaryFile(t, "artifacts/unrelated", "unrelated artifact")
	wheel := filepath.Join("artifacts/pypi", wheelFilename("1.2.3", platform))
	if info, err := os.Stat(wheel); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("ordinary build did not produce a regular nonempty wheel: %v", err)
	}
	content, err := os.ReadFile("artifacts/pypi/python-packages.json")
	if err != nil {
		t.Fatal(err)
	}
	var report packageSet
	if err := json.Unmarshal(content, &report); err != nil {
		t.Fatal(err)
	}
	if report.PackageVersion != "1.2.3" || len(report.Packages) != 1 || report.Packages[0].Filename != filepath.Base(wheel) {
		t.Fatal("ordinary build did not replace the old report with the selected wheel")
	}
}

func TestPythonBuilderOutputBoundaryRefusesAliasesBeforeReset(t *testing.T) {
	for _, alias := range []string{"artifacts", "artifacts/pypi"} {
		t.Run(alias, func(t *testing.T) {
			t.Chdir(t.TempDir())
			t.Setenv("PATH", "")
			writePythonBoundaryFixture(t, testPackageManifest("1.2.3"))
			outside := t.TempDir()
			writePythonBoundaryFile(t, filepath.Join(outside, "sentinel"), "outside sentinel")
			if err := os.MkdirAll(filepath.Dir(alias), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, alias); err != nil {
				t.Fatal(err)
			}
			output := outside
			if alias == "artifacts" {
				output = filepath.Join(outside, "pypi")
			}
			writePythonBoundaryFile(t, filepath.Join(output, "old.whl"), "old wheel")
			writePythonBoundaryFile(t, filepath.Join(output, "python-packages.json"), "old report")
			before, err := os.Lstat(alias)
			if err != nil {
				t.Fatal(err)
			}

			err = run([]string{"build-current"})
			if err == nil || err.Error() != "artifact path traverses a symlink or non-directory" {
				t.Fatalf("want route preflight refusal, not missing-binary failure: %v", err)
			}
			after, err := os.Lstat(alias)
			if err != nil || !os.SameFile(before, after) || after.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("preflight replaced output alias: %v", err)
			}
			assertPythonBoundaryFile(t, filepath.Join(outside, "sentinel"), "outside sentinel")
			assertPythonBoundaryFile(t, filepath.Join(output, "old.whl"), "old wheel")
			assertPythonBoundaryFile(t, filepath.Join(output, "python-packages.json"), "old report")
		})
	}
}

func TestPythonBuilderOutputBoundaryMetadataPrecedesReset(t *testing.T) {
	const synthetic = "api_key=synthetic_boundary_dummy_0123456789"
	for _, field := range []string{"description", "repository.url"} {
		t.Run(field, func(t *testing.T) {
			t.Chdir(t.TempDir())
			t.Setenv("PATH", "")
			manifest := testPackageManifest("1.2.3")
			if field == "description" {
				manifest.Description = synthetic
			} else {
				manifest.Repository.URL = "https://example.test/?" + synthetic
			}
			writePythonBoundaryFixture(t, manifest)
			writePythonBoundaryFile(t, "artifacts/pypi/old.whl", "old wheel")
			writePythonBoundaryFile(t, "artifacts/pypi/python-packages.json", "old report")

			err := run([]string{"build-current"})
			want := "package metadata " + field + " contains a secret-like value"
			if err == nil || err.Error() != want {
				t.Fatalf("want fixed metadata refusal %q, got %v", want, err)
			}
			assertPythonBoundaryFile(t, "artifacts/pypi/old.whl", "old wheel")
			assertPythonBoundaryFile(t, "artifacts/pypi/python-packages.json", "old report")
		})
	}
}

func writePythonBoundaryFixture(t *testing.T, manifest packageJSON) target {
	t.Helper()
	platform, err := currentTarget()
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		"package.json":                        string(content),
		"LICENSE":                             testLicenseContent,
		"python/agentic_proofkit/__init__.py": "",
		"python/agentic_proofkit/__main__.py": "",
		"python/agentic_proofkit/cli.py":      "",
		sourceCLIContractPath:                 testCLIContractContent,
		platform.BinaryPath:                   "synthetic platform bytes, never executed",
	} {
		writePythonBoundaryFile(t, path, body)
	}
	return platform
}

func writePythonBoundaryFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertPythonBoundaryFile(t *testing.T, path, want string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil || string(content) != want {
		t.Fatalf("preserved file %s = %q, %v; want %q", path, content, err, want)
	}
}
