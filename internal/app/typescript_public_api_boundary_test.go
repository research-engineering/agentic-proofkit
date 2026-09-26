package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func boundaryCLIManifest(runtime, types []string) map[string]any {
	copyNames := func(names []string) []string {
		result := append([]string{}, names...)
		sort.Strings(result)
		return result
	}
	return map[string]any{"schemaVersion": 1, "machineContract": "public_api_surfaces", "entries": []any{map[string]any{
		"packageManifestPath": "package.json", "packageName": "@fixture/boundary", "exportKey": ".",
		"exportConditions": []any{map[string]any{"condition": "import", "path": "./index.ts", "sourcePath": "index.ts"}},
		"runtimeExports":   copyNames(runtime), "typeExports": copyNames(types),
	}}}
}

func writeBoundaryCLIFixture(t *testing.T, root, source string, pkg map[string]any) {
	t.Helper()
	if pkg == nil {
		pkg = map[string]any{"name": "@fixture/boundary", "exports": map[string]any{".": map[string]any{"import": "./index.ts"}}}
	}
	data, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal("cannot encode fixture package")
	}
	if os.WriteFile(filepath.Join(root, "package.json"), data, 0600) != nil || os.WriteFile(filepath.Join(root, "index.ts"), []byte(source), 0600) != nil {
		t.Fatal("cannot write fixture")
	}
}

func runBoundaryCLI(t *testing.T, binary, root string, input map[string]any) ([]byte, string, int) {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal("cannot encode manifest")
	}
	command := exec.CommandContext(t.Context(), binary, "typescript-public-api-surfaces", "--input", "-", "--repo-root", root)
	command.Stdin = bytes.NewReader(data)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	code := 0
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			t.Fatal("native CLI did not execute")
		}
		code = exitError.ExitCode()
	}
	return stdout.Bytes(), stderr.String(), code
}

func TestTypeScriptBoundariesNativeCLI(t *testing.T) {
	binary := buildTestBinary(t)
	repo, err := testRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repo, "internal/command/publicapi/testdata/typescript_boundaries.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			ID, Source     string
			Runtime, Types []string
		}
	}
	if json.Unmarshal(data, &corpus) != nil {
		t.Fatal("cannot decode boundary corpus")
	}
	selected := map[string]bool{
		"protected--asi-phantom": true, "protected--asi-reexport": true, "reexport-type-as-alias--fixed": true,
		"property-export--block-lf": true, "type-index-corrected--lf": true, "function-type-arrow--block-ls": true,
		"arrow-function-return-type--fixed": true, "conditional-untyped-arrow": true, "type-qualified--lf": true, "owner--direct-dollar": true,
		"hashbang-export-ghost": true,
	}
	for _, c := range corpus.Cases {
		if !selected[c.ID] {
			continue
		}
		delete(selected, c.ID)
		t.Run(c.ID, func(t *testing.T) {
			root := t.TempDir()
			writeBoundaryCLIFixture(t, root, c.Source, nil)
			check := func(runtime, types []string, want int) {
				t.Helper()
				wire, stderr, code := runBoundaryCLI(t, binary, root, boundaryCLIManifest(runtime, types))
				if code != want || stderr != "" {
					t.Fatalf("CLI status=%d, expected=%d; diagnostic=%q", code, want, stderr)
				}
				var report struct{ Failures []string }
				if json.Unmarshal(wire, &report) != nil || (len(report.Failures) == 0) != (want == 0) {
					t.Fatal("CLI report and status disagree")
				}
			}
			check(c.Runtime, c.Types, 0)
			check(append(append([]string{}, c.Runtime...), "zzUnexpected"), c.Types, 1)
			if len(c.Runtime) > 0 {
				check(c.Runtime[1:], c.Types, 1)
				check(c.Runtime[1:], append(append([]string{}, c.Types...), c.Runtime[0]), 1)
			} else {
				check(c.Runtime, c.Types[1:], 1)
				check(append(append([]string{}, c.Runtime...), c.Types[0]), c.Types[1:], 1)
			}
		})
	}
	if len(selected) != 0 {
		t.Fatal("native boundary controls disappeared from corpus")
	}
	t.Run("late-lexical-error", func(t *testing.T) {
		root := t.TempDir()
		writeBoundaryCLIFixture(t, root, "export const a=1; const bad=1/2;", nil)
		wire, stderr, code := runBoundaryCLI(t, binary, root, boundaryCLIManifest([]string{"a"}, nil))
		if code != 1 || len(wire) != 0 || !strings.Contains(stderr, "unsupported TypeScript public API source grammar") {
			t.Fatal("lexical error reached manifest comparison")
		}
	})
}

func TestTypeScriptReportProjectionNativeNondisclosure(t *testing.T) {
	binary := buildTestBinary(t)
	t.Run("long-ordinary-diagnostic", func(t *testing.T) {
		root := t.TempDir()
		name := strings.Repeat("ordinary_", 512)
		writeBoundaryCLIFixture(t, root, "export const SAFE=1; export const "+name+"=2;", nil)
		wire, stderr, code := runBoundaryCLI(t, binary, root, boundaryCLIManifest([]string{"SAFE"}, nil))
		if code != 1 || stderr != "" {
			t.Fatal("long ordinary mismatch lost its report")
		}
		var report struct{ Failures []string }
		if json.Unmarshal(wire, &report) != nil || len(report.Failures) != 1 || report.Failures[0] != "@fixture/boundary:. runtime exports drift: missing=[] extra=["+name+"]" {
			t.Fatal("native CLI changed a long ordinary diagnostic")
		}
	})
	for _, field := range []string{"source-symbol", "package-export-key", "condition-key"} {
		for _, protected := range []bool{false, true} {
			label := field + "/ordinary"
			name := "unexpectedName"
			if protected {
				label = field + "/protected"
				name = "ghp_" + strings.Repeat("a", 36)
			}
			t.Run(label, func(t *testing.T) {
				root := t.TempDir()
				source := "export const SAFE=1;"
				exports := map[string]any{".": map[string]any{"import": "./index.ts"}}
				switch field {
				case "source-symbol":
					source += "export const " + name + "=2;"
				case "package-export-key":
					exports[name] = nil
				case "condition-key":
					exports["."].(map[string]any)[name] = "./index.ts"
				}
				writeBoundaryCLIFixture(t, root, source, map[string]any{"name": "@fixture/boundary", "exports": exports})
				wire, stderr, code := runBoundaryCLI(t, binary, root, boundaryCLIManifest([]string{"SAFE"}, nil))
				if code != 1 || stderr != "" {
					t.Fatal("failed report was replaced by another CLI outcome")
				}
				var report struct{ Failures []string }
				if json.Unmarshal(wire, &report) != nil || len(report.Failures) != 1 {
					t.Fatal("failed report cardinality changed")
				}
				if protected {
					if bytes.Contains(wire, []byte(name)) || strings.Contains(stderr, name) || report.Failures[0] != "<redacted-diagnostic-value>" {
						t.Fatal("protected observation disclosed by native CLI")
					}
				} else {
					labels := map[string]string{"source-symbol": "@fixture/boundary:. runtime exports", "package-export-key": "@fixture/boundary package.json export keys", "condition-key": "@fixture/boundary exports[.] conditions"}
					if report.Failures[0] != labels[field]+" drift: missing=[] extra=[unexpectedName]" {
						t.Fatal("ordinary CLI diagnostic changed")
					}
				}
			})
		}
	}
}
