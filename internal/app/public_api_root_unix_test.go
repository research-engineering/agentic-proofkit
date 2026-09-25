//go:build darwin || linux

package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

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
