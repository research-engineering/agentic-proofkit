package publicapi

import (
	"encoding/json"
	"fmt"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyTypeScriptPackagePublicAPISurfaces(t *testing.T) {
	repoRoot := writeTypeScriptPackageFixture(t)
	input := publicAPIManifest()

	output, exitCode, err := Verify(input, Options{RepoRoot: repoRoot})
	if err != nil {
		t.Fatalf("verify public API: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected success, got exitCode=%d output=%#v", exitCode, output)
	}
	if output["entryCount"] != 1 {
		t.Fatalf("entryCount=%v want 1", output["entryCount"])
	}
}

func TestVerifyTypeScriptPackagePublicAPIAcceptsCompiledTargetsForScannedSource(t *testing.T) {
	repoRoot := writeTypeScriptPackageFixture(t)
	packageRoot := filepath.Join(repoRoot, "packages", "alpha")
	writeJSON(t, filepath.Join(packageRoot, "package.json"), map[string]any{
		"name": "@example/alpha",
		"exports": map[string]any{
			".": map[string]any{
				"default": "./dist/index.js",
				"types":   "./dist/index.d.ts",
			},
			"./internal": nil,
		},
	})
	input := publicAPIManifest()
	entry := input["entries"].([]any)[0].(map[string]any)
	entry["exportConditions"] = []any{
		map[string]any{"condition": "default", "path": "./dist/index.js"},
		map[string]any{"condition": "types", "path": "./dist/index.d.ts"},
	}

	output, exitCode, err := Verify(input, Options{RepoRoot: repoRoot})
	if err != nil {
		t.Fatalf("verify public API: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected compiled target success, got exitCode=%d output=%#v", exitCode, output)
	}
}

func TestVerifyTypeScriptPackagePublicAPIRejectsSecretLikeManifestText(t *testing.T) {
	repoRoot := writeTypeScriptPackageFixture(t)
	secretLike := "Authorization: Bearer abcdefghijklmnop"
	input := publicAPIManifest()
	entry := input["entries"].([]any)[0].(map[string]any)
	entry["packageName"] = secretLike

	_, exitCode, err := Verify(input, Options{RepoRoot: repoRoot})
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "secret-like values") {
		t.Fatalf("Verify() exitCode=%d error=%v, want secret-like rejection", exitCode, err)
	}
	if strings.Contains(err.Error(), secretLike) {
		t.Fatalf("Verify() leaked secret-like manifest text: %v", err)
	}
}

func TestVerifyTypeScriptPackagePublicAPIRejectsNonTypeScriptSource(t *testing.T) {
	repoRoot := writeTypeScriptPackageFixture(t)
	input := publicAPIManifest()
	entry := input["entries"].([]any)[0].(map[string]any)
	entry["source"] = "src/index.go"

	_, exitCode, err := Verify(input, Options{RepoRoot: repoRoot})
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "src/*.ts") {
		t.Fatalf("expected TypeScript source boundary failure, exitCode=%d err=%v", exitCode, err)
	}
}

func TestVerifyTypeScriptPackagePublicAPIRejectsExportTargetDifferentFromScannedSource(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.006943269310710743628834650487878767615578781676283703895362243693196266764140")
	repoRoot := writeTypeScriptPackageFixture(t)
	packageRoot := filepath.Join(repoRoot, "packages", "alpha")
	if err := os.WriteFile(filepath.Join(packageRoot, "src", "other.ts"), []byte(`export const OTHER = 1;`), 0o600); err != nil {
		t.Fatalf("write alternate source: %v", err)
	}
	writeJSON(t, filepath.Join(packageRoot, "package.json"), map[string]any{
		"name": "@example/alpha",
		"exports": map[string]any{
			".": map[string]any{
				"import": "./src/other.ts",
				"types":  "./src/other.ts",
			},
			"./internal": nil,
		},
	})
	input := publicAPIManifest()
	entry := input["entries"].([]any)[0].(map[string]any)
	entry["exportConditions"] = []any{
		map[string]any{"condition": "import", "path": "./src/other.ts"},
		map[string]any{"condition": "types", "path": "./src/other.ts"},
	}

	output, exitCode, err := Verify(input, Options{RepoRoot: repoRoot})
	if err != nil {
		t.Fatalf("Verify() error=%v, want report failure", err)
	}
	if exitCode != 1 {
		t.Fatalf("Verify() exitCode=%d output=%#v, want target/source failure", exitCode, output)
	}
	if !strings.Contains(fmt.Sprint(output["failures"]), "must match scanned source") {
		t.Fatalf("failures=%#v, want scanned source mismatch", output["failures"])
	}
}

func TestVerifyTypeScriptPackagePublicAPIRejectsExportStar(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.115680445627116622094001089796073200022717487136984640379014309614998296843761")
	repoRoot := writeTypeScriptPackageFixture(t)
	sourcePath := filepath.Join(repoRoot, "packages", "alpha", "src", "index.ts")
	if err := os.WriteFile(sourcePath, []byte(`export * from "./internal";`), 0o600); err != nil {
		t.Fatalf("rewrite source: %v", err)
	}

	_, exitCode, err := Verify(publicAPIManifest(), Options{RepoRoot: repoRoot})
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "export *") {
		t.Fatalf("expected export-star failure, exitCode=%d err=%v", exitCode, err)
	}
}

func TestVerifyTypeScriptPackagePublicAPIRejectsSymlinkEscapedSource(t *testing.T) {
	repoRoot := writeTypeScriptPackageFixture(t)
	outsideRoot := t.TempDir()
	outsideSource := filepath.Join(outsideRoot, "index.ts")
	if err := os.WriteFile(outsideSource, []byte(`export const VALUE = 1; export function makeThing() { return { id: "x" }; } export interface Thing { id: string } export type Mode = "on";`), 0o600); err != nil {
		t.Fatalf("write outside source: %v", err)
	}
	sourcePath := filepath.Join(repoRoot, "packages", "alpha", "src", "index.ts")
	if err := os.Remove(sourcePath); err != nil {
		t.Fatalf("remove source: %v", err)
	}
	if err := os.Symlink(outsideSource, sourcePath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	_, exitCode, err := Verify(publicAPIManifest(), Options{RepoRoot: repoRoot})
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "must resolve inside repo root") {
		t.Fatalf("Verify() exitCode=%d error=%v, want symlink escape rejection", exitCode, err)
	}
}

func TestVerifyTypeScriptPackagePublicAPIRejectsAmbiguousPackageManifest(t *testing.T) {
	cases := []struct {
		name     string
		manifest string
		want     string
	}{
		{name: "duplicate name", manifest: `{"name":"@example/alpha","name":"@example/beta","exports":{".":{"import":"./src/index.ts","types":"./src/index.ts"},"./internal":null}}`, want: "duplicate object key"},
		{name: "duplicate exports", manifest: `{"name":"@example/alpha","exports":{},"exports":{".":{"import":"./src/index.ts","types":"./src/index.ts"},"./internal":null}}`, want: "duplicate object key"},
		{name: "trailing value", manifest: `{"name":"@example/alpha","exports":{}} {"name":"@example/beta"}`, want: "multiple JSON values"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			repoRoot := writeTypeScriptPackageFixture(t)
			manifestPath := filepath.Join(repoRoot, "packages", "alpha", "package.json")
			if err := os.WriteFile(manifestPath, []byte(item.manifest), 0o600); err != nil {
				t.Fatalf("rewrite manifest: %v", err)
			}

			_, exitCode, err := Verify(publicAPIManifest(), Options{RepoRoot: repoRoot})
			if exitCode != 1 || err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("Verify() exitCode=%d error=%v, want %q", exitCode, err, item.want)
			}
		})
	}
}

func TestVerifyTypeScriptPackagePublicAPIRejectsDuplicatePackageIdentity(t *testing.T) {
	repoRoot := writeTypeScriptPackageFixture(t)
	duplicateRoot := filepath.Join(repoRoot, "packages", "beta")
	if err := os.MkdirAll(duplicateRoot, 0o755); err != nil {
		t.Fatalf("mkdir duplicate package: %v", err)
	}
	writeJSON(t, filepath.Join(duplicateRoot, "package.json"), map[string]any{
		"name":    "@example/alpha",
		"exports": map[string]any{},
	})

	_, exitCode, err := Verify(publicAPIManifest(), Options{RepoRoot: repoRoot})
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "duplicate package name @example/alpha") {
		t.Fatalf("Verify() exitCode=%d error=%v, want duplicate package identity", exitCode, err)
	}
}

func TestCollectExportsAcceptsMultilineReexports(t *testing.T) {
	source := strings.Join([]string{
		"export {",
		"  VALUE,",
		"  makeThing,",
		"} from \"./thing.js\";",
		"export type {",
		"  Mode,",
		"  Thing,",
		"} from \"./thing.js\";",
	}, "\n")

	runtimeExports, typeExports, err := CollectExports(source)
	if err != nil {
		t.Fatalf("collect exports: %v", err)
	}
	assertStringSlice(t, runtimeExports, []string{"VALUE", "makeThing"})
	assertStringSlice(t, typeExports, []string{"Mode", "Thing"})
}

func TestCollectExportsClassifiesInlineTypeReexports(t *testing.T) {
	source := strings.Join([]string{
		"export { type Mode, VALUE, type Thing as PublicThing } from \"./thing.js\";",
		"export { type as runtimeType } from \"./named-type.js\";",
		"export {",
		"  type Options,",
		"  makeThing,",
		"} from \"./more.js\";",
	}, "\n")

	runtimeExports, typeExports, err := CollectExports(source)
	if err != nil {
		t.Fatalf("collect exports: %v", err)
	}
	assertStringSlice(t, runtimeExports, []string{"VALUE", "makeThing", "runtimeType"})
	assertStringSlice(t, typeExports, []string{"Mode", "Options", "PublicThing"})
}

func TestCollectExportsDoesNotInventExportsFromCommaBearingInitializers(t *testing.T) {
	source := strings.Join([]string{
		"export const a = {x: 1, b: 2}, c: Array<string> = [\"x\", \"y\"];",
		"export let d = makeValue<{left: string, right: string}>();",
		"export const genericCall = make<string, number>();",
		"export const directMatcher = /,/, matcherWithClass = /[a,b]/;",
		"export const isSmall = limit < 10, fallback = 1;",
	}, "\n")

	runtimeExports, typeExports, err := CollectExports(source)
	if err != nil {
		t.Fatalf("collect exports: %v", err)
	}
	assertStringSlice(t, runtimeExports, []string{"a", "c", "d", "directMatcher", "fallback", "genericCall", "isSmall", "matcherWithClass"})
	assertStringSlice(t, typeExports, []string{})
}

func TestCollectExportsAcceptsRegexLiteralReturnedByArrowInitializer(t *testing.T) {
	runtimeExports, typeExports, err := CollectExports("export const matcher = () => /,/, next = 1;")
	if err != nil {
		t.Fatalf("collect arrow regex initializer exports: %v", err)
	}
	assertStringSlice(t, runtimeExports, []string{"matcher", "next"})
	assertStringSlice(t, typeExports, []string{})
}

func TestCollectExportsIgnoresCommentsStringsAndTemplates(t *testing.T) {
	source := strings.Join([]string{
		"/* export const BLOCK_GHOST = 1; */",
		"// export const LINE_GHOST = 1;",
		`const text = "export const STRING_GHOST = 1;";`,
		`const continued = "still a string \`,
		`export const CONTINUATION_GHOST = 1;";`,
		"const template = `export const TEMPLATE_GHOST = 1;`;",
		"export const REAL = 1;",
	}, "\n")

	runtimeExports, typeExports, err := CollectExports(source)
	if err != nil {
		t.Fatalf("collect exports: %v", err)
	}
	assertStringSlice(t, runtimeExports, []string{"REAL"})
	assertStringSlice(t, typeExports, []string{})
}

func TestScanCacheRejectsOversizedSource(t *testing.T) {
	repoRoot := t.TempDir()
	resolvedRoot, err := filepath.EvalSymlinks(repoRoot)
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	path := filepath.Join(repoRoot, "oversized.ts")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create oversized source: %v", err)
	}
	if err := file.Truncate(maxSourceFileBytes + 1); err != nil {
		file.Close()
		t.Fatalf("truncate oversized source: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close oversized source: %v", err)
	}
	scan := newScanCache(resolvedRoot, maxAggregateScanBytes)
	if _, _, err := scan.readFile(path, "fixture source", maxSourceFileBytes); err == nil || !strings.Contains(err.Error(), "8 MiB") {
		t.Fatalf("scan.readFile() error=%v, want bounded file rejection", err)
	}
}

func TestVerifyTypeScriptPackagePublicAPICachesRepeatedCanonicalSources(t *testing.T) {
	repoRoot := writeTypeScriptPackageFixture(t)
	packageRoot := filepath.Join(repoRoot, "packages", "alpha")
	manifestPath := filepath.Join(packageRoot, "package.json")
	sourcePath := filepath.Join(packageRoot, "src", "index.ts")
	writeJSON(t, manifestPath, map[string]any{
		"name": "@example/alpha",
		"exports": map[string]any{
			".": map[string]any{
				"import": "./src/index.ts",
				"types":  "./src/index.ts",
			},
			"./internal": nil,
			"./secondary": map[string]any{
				"import": "./src/index.ts",
				"types":  "./src/index.ts",
			},
		},
	})
	input := publicAPIManifest()
	input["entries"] = append(input["entries"].([]any), map[string]any{
		"packageName":      "@example/alpha",
		"exportKey":        "./secondary",
		"source":           "src/index.ts",
		"runtimeExports":   []any{"VALUE", "makeThing"},
		"typeExports":      []any{"Mode", "Thing"},
		"deniedExportKeys": []any{"./internal"},
		"exportConditions": []any{
			map[string]any{"condition": "import", "path": "./src/index.ts"},
			map[string]any{"condition": "types", "path": "./src/index.ts"},
		},
	})
	manifestInfo, err := os.Stat(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		t.Fatal(err)
	}

	output, exitCode, err := verifyWithScanBudget(input, Options{RepoRoot: repoRoot}, manifestInfo.Size()+sourceInfo.Size())
	if err != nil || exitCode != 0 {
		t.Fatalf("verify repeated source: exitCode=%d error=%v output=%#v", exitCode, err, output)
	}
}

func TestScanCacheRejectsAggregateBytesAcrossUniqueFiles(t *testing.T) {
	repoRoot := t.TempDir()
	firstPath := filepath.Join(repoRoot, "first.ts")
	secondPath := filepath.Join(repoRoot, "second.ts")
	if err := os.WriteFile(firstPath, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	scan := newScanCache(resolvedRoot, 10)
	if _, _, err := scan.readFile(firstPath, "first source", maxSourceFileBytes); err != nil {
		t.Fatalf("read first source: %v", err)
	}
	if _, _, err := scan.readFile(secondPath, "second source", maxSourceFileBytes); err == nil || !strings.Contains(err.Error(), "aggregate file-read limit") {
		t.Fatalf("scan.readFile() error=%v, want aggregate budget rejection", err)
	}
}

func TestReadPackageManifestRejectsOversizedMetadata(t *testing.T) {
	repoRoot := t.TempDir()
	manifestPath := filepath.Join(repoRoot, "package.json")
	file, err := os.Create(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxPackageManifestBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readPackageManifest(newScanCache(resolvedRoot, maxAggregateScanBytes), manifestPath); err == nil || !strings.Contains(err.Error(), "256 KiB") {
		t.Fatalf("readPackageManifest() error=%v, want package metadata bound rejection", err)
	}
}

func TestPublicAPIAdmissionRejectsAggregateResourceBudgets(t *testing.T) {
	manifest := map[string]any{
		"schemaVersion": json.Number("1"), "machineContract": defaultMachineContract,
		"entries": make([]any, maxManifestEntries+1),
	}
	if _, err := admitManifest(manifest, defaultMachineContract); err == nil || !strings.Contains(err.Error(), "entry limit") {
		t.Fatalf("admitManifest() error=%v, want aggregate entry limit", err)
	}

	repoRoot := t.TempDir()
	packagesRoot := filepath.Join(repoRoot, "packages")
	if err := os.MkdirAll(packagesRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= maxPackageDirEntries; index++ {
		if err := os.WriteFile(filepath.Join(packagesRoot, fmt.Sprintf("entry-%04d", index)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	resolvedRoot, err := filepath.EvalSymlinks(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := packageDirs(newScanCache(resolvedRoot, maxAggregateScanBytes), "packages"); err == nil || !strings.Contains(err.Error(), "entry limit") {
		t.Fatalf("packageDirs() error=%v, want bounded directory admission", err)
	}
}

func writeTypeScriptPackageFixture(t *testing.T) string {
	t.Helper()
	repoRoot := t.TempDir()
	packageRoot := filepath.Join(repoRoot, "packages", "alpha")
	if err := os.MkdirAll(filepath.Join(packageRoot, "src"), 0o755); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	writeJSON(t, filepath.Join(packageRoot, "package.json"), map[string]any{
		"name": "@example/alpha",
		"exports": map[string]any{
			".": map[string]any{
				"import": "./src/index.ts",
				"types":  "./src/index.ts",
			},
			"./internal": nil,
		},
	})
	if err := os.WriteFile(filepath.Join(packageRoot, "src", "index.ts"), []byte(strings.Join([]string{
		"export interface Thing { id: string }",
		"export type Mode = \"on\" | \"off\";",
		"export const VALUE = 1;",
		"export function makeThing(): Thing { return { id: \"x\" }; }",
	}, "\n")), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	return repoRoot
}

func publicAPIManifest() map[string]any {
	return map[string]any{
		"schemaVersion":   json.Number("1"),
		"machineContract": "public_api_surfaces",
		"entries": []any{
			map[string]any{
				"packageName":      "@example/alpha",
				"exportKey":        ".",
				"source":           "src/index.ts",
				"runtimeExports":   []any{"VALUE", "makeThing"},
				"typeExports":      []any{"Mode", "Thing"},
				"deniedExportKeys": []any{"./internal"},
				"exportConditions": []any{
					map[string]any{"condition": "import", "path": "./src/index.ts"},
					map[string]any{"condition": "types", "path": "./src/index.ts"},
				},
			},
		},
	}
}

func assertStringSlice(t *testing.T, actual []string, expected []string) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("slice length=%d want %d; actual=%v", len(actual), len(expected), actual)
	}
	for index, expectedValue := range expected {
		if actual[index] != expectedValue {
			t.Fatalf("slice[%d]=%q want %q; actual=%v", index, actual[index], expectedValue, actual)
		}
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	if err := os.WriteFile(path, append(content, '\n'), 0o600); err != nil {
		t.Fatalf("write json %s: %v", path, err)
	}
}
