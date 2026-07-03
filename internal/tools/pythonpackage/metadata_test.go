package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPythonPackageReadersRejectAmbiguousJSON(t *testing.T) {
	cases := []struct {
		name    string
		content string
		read    func(string) error
		want    string
	}{
		{
			name:    "package manifest duplicate key",
			content: `{"name":"agentic-proofkit","name":"other","version":"1.2.3","license":"MIT","repository":{"url":"https://example.test/repo"}}`,
			read: func(path string) error {
				return withPackageJSON(t, path, func() error {
					_, err := readPackageJSON()
					return err
				})
			},
			want: "duplicate object key",
		},
		{
			name:    "package set trailing value",
			content: `{"artifactKind":"proofkit.python-package-set.v1","schemaVersion":1,"packageName":"agentic-proofkit","packageVersion":"1.2.3","packages":[]} true`,
			read: func(path string) error {
				_, err := readPackageSet(path)
				return err
			},
			want: "multiple JSON values",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(path, []byte(item.content), 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}
			err := item.read(path)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("reader error = %v, want %q", err, item.want)
			}
		})
	}
}

func TestReadPackageJSONRejectsUnsafeWheelMetadata(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "filename unsafe semver prerelease",
			content: `{"name":"agentic-proofkit","version":"1.2.3-beta.1","description":"Proofkit CLI","license":"MIT","repository":{"url":"https://example.test/repo"}}`,
			want:    "PEP 440-compatible wheel version",
		},
		{
			name:    "header injection",
			content: `{"name":"agentic-proofkit","version":"1.2.3","description":"Proofkit CLI\nClassifier: unsafe","license":"MIT","repository":{"url":"https://example.test/repo"}}`,
			want:    "single-line metadata field",
		},
		{
			name:    "missing description",
			content: `{"name":"agentic-proofkit","version":"1.2.3","license":"MIT","repository":{"url":"https://example.test/repo"}}`,
			want:    "must include description",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "package.json")
			if err := os.WriteFile(path, []byte(item.content), 0o600); err != nil {
				t.Fatalf("write package.json: %v", err)
			}
			err := withPackageJSON(t, path, func() error {
				_, err := readPackageJSON()
				return err
			})
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("readPackageJSON() error = %v, want %q", err, item.want)
			}
		})
	}
}

func TestVerifyWheelContentsRequiresExactWheelMetadata(t *testing.T) {
	target := releaseTargets()[0]
	version := "1.2.3"
	path := filepath.Join(t.TempDir(), "wheel.whl")
	writeMinimalWheel(t, path, version, wheelMetadata(target)+"Tag: py3-none-conflicting\n")

	err := verifyWheelContents(path, version, target)
	if err == nil || !strings.Contains(err.Error(), "WHEEL metadata must match release platform target") {
		t.Fatalf("verifyWheelContents() error=%v, want exact WHEEL metadata rejection", err)
	}
}

func writeMinimalWheel(t *testing.T, path string, version string, wheel string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create wheel: %v", err)
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	defer writer.Close()
	distInfo := distInfoDir(version)
	entries := map[string]string{
		"agentic_proofkit/__init__.py":          "",
		"agentic_proofkit/__main__.py":          "",
		"agentic_proofkit/cli.py":               "",
		"agentic_proofkit/bin/agentic-proofkit": "binary",
		distInfo + "/METADATA":                  "Metadata-Version: 2.1\n",
		distInfo + "/WHEEL":                     wheel,
		distInfo + "/entry_points.txt":          entryPoints(),
		distInfo + "/RECORD":                    "",
	}
	for name, content := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
}

func withPackageJSON(t *testing.T, source string, fn func() error) error {
	t.Helper()
	root := t.TempDir()
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), content, 0o600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir temp root: %v", err)
	}
	defer func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()
	return fn()
}
