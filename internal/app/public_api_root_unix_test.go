//go:build darwin || linux

package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPublicAPIScannerPreservesNativeRootPermissions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission controls require an unprivileged process")
	}
	for _, test := range []struct {
		name       string
		parentMode os.FileMode
		rootMode   os.FileMode
		empty      bool
		passed     bool
	}{
		{"readable", 0o700, 0o700, false, true},
		{"search-only-parent", 0o111, 0o700, false, true},
		{"nonsearchable-parent", 0o400, 0o700, false, false},
		{"read-only-root-empty", 0o700, 0o400, true, true},
		{"read-only-root-nonempty", 0o700, 0o400, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := filepath.Join(t.TempDir(), "parent")
			root := filepath.Join(parent, "repo")
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			for path, content := range map[string]string{
				"package.json": `{"name":"@example/alpha","exports":{".":{"import":"./index.ts"}}}`,
				"index.ts":     "export const VALUE = 1;\n",
			} {
				if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() {
				if err := os.Chmod(parent, 0o700); err != nil {
					t.Error(err)
				}
				if err := os.Chmod(root, 0o700); err != nil {
					t.Error(err)
				}
			})
			if err := os.Chmod(root, test.rootMode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(parent, test.parentMode); err != nil {
				t.Fatal(err)
			}
			if test.parentMode == 0o111 {
				file, err := os.Open(parent)
				if file != nil {
					_ = file.Close()
				}
				if !os.IsPermission(err) {
					t.Fatalf("search-only parent must refuse a read open: %v", err)
				}
			}
			// Native acquisition is the compatibility control, independent of the scanner.
			native, err := os.OpenRoot(root)
			if test.parentMode == 0o400 {
				if native != nil {
					_ = native.Close()
				}
				if !os.IsPermission(err) {
					t.Fatalf("native traversal must reject no-search parent: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				var lookupErr error
				if test.rootMode == 0o400 {
					_, lookupErr = native.Stat(".")
				}
				if err := native.Close(); err != nil {
					t.Fatal(err)
				}
				if test.rootMode == 0o400 && !os.IsPermission(lookupErr) {
					t.Fatalf("read-only root must refuse relative lookup: %v", lookupErr)
				}
			}
			input := map[string]any{
				"schemaVersion": json.Number("1"), "machineContract": "public_api_surfaces",
				"entries": []any{map[string]any{
					"packageName": "@example/alpha", "packageManifestPath": "package.json", "exportKey": ".",
					"runtimeExports": []any{"VALUE"}, "typeExports": []any{}, "deniedExportKeys": []any{},
					"exportConditions": []any{map[string]any{"condition": "import", "path": "./index.ts", "sourcePath": "index.ts"}},
				}},
			}
			if test.empty {
				input["entries"] = []any{}
			}
			args := []string{"typescript-public-api-surfaces", "--input", "-", "--repo-root", root}
			if test.passed {
				output := runAppJSON(t, args, input)
				wantCount := json.Number("1")
				if test.empty {
					wantCount = json.Number("0")
				}
				if output["entryCount"] != wantCount {
					t.Fatalf("unexpected entryCount: %#v", output)
				}
			} else {
				encoded, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				var stdout, stderr bytes.Buffer
				if exit := Run(t.Context(), args, bytes.NewReader(encoded), &stdout, &stderr); exit != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "permission denied") {
					t.Fatalf("permission refusal lost: exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
				}
			}
		})
	}
}

func TestPublicAPIScannerPreservesMaximumNativeRootPaths(t *testing.T) {
	for _, length := range []int{unix.PathMax - 3, unix.PathMax - 2, unix.PathMax - 1} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for len(root)+102 < length {
				root += "/" + strings.Repeat("a", 100)
			}
			remaining := length - len(root) - 1
			if remaining < 1 || remaining > 255 {
				t.Fatal("invalid path-boundary fixture")
			}
			root += "/" + strings.Repeat("b", remaining)
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			// This independent native open proves the original pathname is valid.
			directory, err := os.OpenRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = directory.Close() })
			for path, content := range map[string]string{
				"package.json": `{"name":"@example/alpha","exports":{".":{"import":"./index.ts"}}}`,
				"index.ts":     "export const VALUE = 1;\n",
			} {
				if err := directory.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			input := map[string]any{
				"schemaVersion": json.Number("1"), "machineContract": "public_api_surfaces",
				"entries": []any{map[string]any{
					"packageName": "@example/alpha", "packageManifestPath": "package.json", "exportKey": ".",
					"runtimeExports": []any{"VALUE"}, "typeExports": []any{}, "deniedExportKeys": []any{},
					"exportConditions": []any{map[string]any{"condition": "import", "path": "./index.ts", "sourcePath": "index.ts"}},
				}},
			}
			output := runAppJSON(t, []string{"typescript-public-api-surfaces", "--input", "-", "--repo-root", root}, input)
			if output["entryCount"] != json.Number("1") {
				t.Fatalf("scanner did not verify the nonempty manifest: %#v", output)
			}
		})
	}
}
