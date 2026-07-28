package publicapi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
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

func TestVerifyTypeScriptRootPackagePublicAPISurfaces(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(repoRoot, "src", "index.ts"),
		[]byte("export const VALUE = 1;\nexport function makeThing() {}\nexport type Mode = string;\nexport interface Thing {}\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(repoRoot, "package.json"), map[string]any{
		"name": "@example/alpha",
		"exports": map[string]any{
			".": map[string]any{
				"import": "./src/index.ts",
				"types":  "./src/index.ts",
			},
			"./internal": nil,
		},
	})
	input := publicAPIManifest()
	item := input["entries"].([]any)[0].(map[string]any)
	item["packageManifestPath"] = "package.json"
	for _, raw := range item["exportConditions"].([]any) {
		raw.(map[string]any)["sourcePath"] = "src/index.ts"
	}

	output, exitCode, err := Verify(input, Options{RepoRoot: repoRoot})
	if err != nil || exitCode != 0 {
		t.Fatalf("Verify() exit=%d error=%v output=%#v, want root-package success", exitCode, err, output)
	}
}

func TestVerifyTypeScriptPackagePublicAPIAcceptsExplicitSourceMappingsForCompiledTargets(t *testing.T) {
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
		map[string]any{"condition": "default", "path": "./dist/index.js", "sourcePath": "packages/alpha/src/index.ts"},
		map[string]any{"condition": "types", "path": "./dist/index.d.ts", "sourcePath": "packages/alpha/src/index.ts"},
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

func TestVerifyTypeScriptPackagePublicAPIRejectsUnsupportedSourceSyntaxExtensions(t *testing.T) {
	for _, sourcePath := range []string{"packages/alpha/src/index.go", "packages/alpha/src/index.tsx"} {
		t.Run(filepath.Ext(sourcePath), func(t *testing.T) {
			repoRoot := writeTypeScriptPackageFixture(t)
			input := publicAPIManifest()
			entry := input["entries"].([]any)[0].(map[string]any)
			entry["exportConditions"].([]any)[0].(map[string]any)["sourcePath"] = sourcePath

			_, exitCode, err := Verify(input, Options{RepoRoot: repoRoot})
			if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "non-JSX TypeScript source") {
				t.Fatalf("expected source syntax boundary failure, exitCode=%d err=%v", exitCode, err)
			}
		})
	}
}

func TestVerifyTypeScriptPackagePublicAPIRejectsExportsFromDifferentDeclaredSource(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.045293983925342815526031937349730030851244261191887869042173792304502947213298")
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
		map[string]any{"condition": "import", "path": "./src/other.ts", "sourcePath": "packages/alpha/src/other.ts"},
		map[string]any{"condition": "types", "path": "./src/other.ts", "sourcePath": "packages/alpha/src/other.ts"},
	}

	output, exitCode, err := Verify(input, Options{RepoRoot: repoRoot})
	if err != nil {
		t.Fatalf("Verify() error=%v, want report failure", err)
	}
	if exitCode != 1 {
		t.Fatalf("Verify() exitCode=%d output=%#v, want target/source failure", exitCode, output)
	}
	if !strings.Contains(fmt.Sprint(output["failures"]), "runtime exports drift") {
		t.Fatalf("failures=%#v, want declared source export mismatch", output["failures"])
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
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "absolute symlink target") {
		t.Fatalf("Verify() exitCode=%d error=%v, want symlink escape rejection", exitCode, err)
	}
}

func TestVerifyTypeScriptPackagePublicAPIRejectsSymlinkToTSX(t *testing.T) {
	repoRoot := writeTypeScriptPackageFixture(t)
	sourcePath := filepath.Join(repoRoot, "packages", "alpha", "src", "index.ts")
	tsxPath := filepath.Join(repoRoot, "packages", "alpha", "src", "index.tsx")
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tsxPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("index.tsx", sourcePath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	_, exitCode, err := Verify(publicAPIManifest(), Options{RepoRoot: repoRoot})
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "non-JSX TypeScript source") {
		t.Fatalf("Verify() exitCode=%d error=%v, want canonical TSX target rejection", exitCode, err)
	}
}

func TestVerifyAcceptsStableRelativeInRootSymlink(t *testing.T) {
	repoRoot := writeTypeScriptPackageFixture(t)
	sourcePath := filepath.Join(repoRoot, "packages", "alpha", "src", "index.ts")
	targetPath := filepath.Join(repoRoot, "packages", "alpha", "src", "real.ts")
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.ts", sourcePath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	output, exitCode, err := Verify(publicAPIManifest(), Options{RepoRoot: repoRoot})
	if err != nil || exitCode != 0 {
		t.Fatalf("Verify() exit=%d error=%v output=%#v, want confined relative symlink success", exitCode, err, output)
	}
}

func TestVerifyRejectsDeterministicSymlinkSwap(t *testing.T) {
	for _, item := range []struct {
		name string
		swap func(t *testing.T, repoRoot, outsideRoot string)
	}{
		{
			name: "leaf source swap",
			swap: func(t *testing.T, repoRoot, outsideRoot string) {
				sourcePath := filepath.Join(repoRoot, "packages", "alpha", "src", "index.ts")
				if err := os.Remove(sourcePath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(outsideRoot, "index.ts"), sourcePath); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "ancestor directory swap",
			swap: func(t *testing.T, repoRoot, outsideRoot string) {
				sourceDir := filepath.Join(repoRoot, "packages", "alpha", "src")
				if err := os.Rename(sourceDir, sourceDir+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outsideRoot, sourceDir); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			repoRoot := writeTypeScriptPackageFixture(t)
			outsideRoot := t.TempDir()
			if err := os.WriteFile(filepath.Join(outsideRoot, "index.ts"), []byte(`export const SENTINEL = "outside";`), 0o600); err != nil {
				t.Fatal(err)
			}
			swapped := false
			scanAdmissionBarrier = func(stage, lexical string) {
				if swapped || stage != "canonical_resolved" || lexical != "packages/alpha/src/index.ts" {
					return
				}
				swapped = true
				item.swap(t, repoRoot, outsideRoot)
			}
			t.Cleanup(func() { scanAdmissionBarrier = nil })

			output, exitCode, err := Verify(publicAPIManifest(), Options{RepoRoot: repoRoot})
			if !swapped {
				t.Fatal("deterministic scan barrier was not reached")
			}
			if exitCode != 1 || err == nil {
				t.Fatalf("Verify() exit=%d error=%v output=%#v, want fail-closed swap rejection", exitCode, err, output)
			}
			if strings.Contains(fmt.Sprint(output), "SENTINEL") || strings.Contains(err.Error(), "SENTINEL") {
				t.Fatalf("outside sentinel leaked through confined scanner: output=%#v error=%v", output, err)
			}
		})
	}
}

func TestVerifyPinsPackageRootAcrossInRootSiblingSwap(t *testing.T) {
	repoRoot := writeTypeScriptPackageFixture(t)
	alphaSource := filepath.Join(repoRoot, "packages", "alpha", "src", "index.ts")
	if err := os.WriteFile(alphaSource, []byte("export const ORIGINAL = 1;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	swapped := false
	scanAdmissionBarrier = func(stage, lexical string) {
		if swapped || stage != "canonical_resolved" || lexical != "packages/alpha/src/index.ts" {
			return
		}
		swapped = true
		packagesDir := filepath.Join(repoRoot, "packages")
		betaSourceDir := filepath.Join(packagesDir, "beta", "src")
		if err := os.MkdirAll(betaSourceDir, 0o755); err != nil {
			t.Fatal(err)
		}
		betaSource := "export const VALUE = 1;\nexport function makeThing() {}\nexport type Mode = string;\nexport interface Thing {}\n"
		if err := os.WriteFile(filepath.Join(betaSourceDir, "index.ts"), []byte(betaSource), 0o600); err != nil {
			t.Fatal(err)
		}
		alphaDir := filepath.Join(packagesDir, "alpha")
		if err := os.Rename(alphaDir, alphaDir+"-original"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("beta", alphaDir); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { scanAdmissionBarrier = nil })

	output, exitCode, err := Verify(publicAPIManifest(), Options{RepoRoot: repoRoot})
	if !swapped {
		t.Fatal("deterministic scan barrier was not reached")
	}
	if err != nil || exitCode != 1 {
		t.Fatalf("Verify() exit=%d error=%v output=%#v, want pinned original package source mismatch", exitCode, err, output)
	}
	failures := fmt.Sprint(output["failures"])
	if !strings.Contains(failures, "ORIGINAL") || strings.Contains(failures, "SENTINEL") {
		t.Fatalf("Verify() failures=%s, want proof that the pinned alpha source, not the sibling, was read", failures)
	}
}

func TestScanCacheBindsBytesToFirstCanonicalIdentityAcrossSymlinkRetarget(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoRoot, "a.ts"), []byte("A"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "b.ts"), []byte("B"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(repoRoot, "entry.ts")
	if err := os.Symlink("a.ts", linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	scan := newScanCache(repoRoot, maxAggregateScanBytes)
	if scan.initErr != nil {
		t.Fatal(scan.initErr)
	}
	t.Cleanup(func() {
		if err := scan.root.Close(); err != nil {
			t.Errorf("close scan root: %v", err)
		}
	})

	firstContent, firstCanonical, err := scan.readFile("entry.ts", "fixture source", maxSourceFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	if firstContent != "A" || firstCanonical != "a.ts" {
		t.Fatalf("first read=(%q, %q), want bytes and canonical identity from a.ts", firstContent, firstCanonical)
	}
	if err := os.Remove(linkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b.ts", linkPath); err != nil {
		t.Fatal(err)
	}
	currentCanonical, err := scan.canonicalRelativePath("entry.ts", "fixture source")
	if err != nil {
		t.Fatal(err)
	}
	if currentCanonical != "b.ts" {
		t.Fatalf("retargeted lexical path resolves to %q, want b.ts", currentCanonical)
	}

	secondContent, secondCanonical, err := scan.readFile("entry.ts", "fixture source", maxSourceFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	if secondContent != "A" || secondCanonical != "a.ts" {
		t.Fatalf("cached read=(%q, %q), want indivisible first-admission snapshot (A, a.ts)", secondContent, secondCanonical)
	}
}

func TestCanonicalSourceSnapshotRejectsChangedCrossAliasAdmission(t *testing.T) {
	originalContent := []byte("export const ALPHA = 1;")
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, targetPath string, before os.FileInfo)
	}{
		{
			name: "identity drift with stable digest",
			mutate: func(t *testing.T, targetPath string, before os.FileInfo) {
				replacementPath := targetPath + ".replacement"
				if err := os.WriteFile(replacementPath, originalContent, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(targetPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacementPath, targetPath); err != nil {
					t.Fatal(err)
				}
				after, err := os.Stat(targetPath)
				if err != nil {
					t.Fatal(err)
				}
				if os.SameFile(before, after) {
					t.Fatal("replacement retained file identity; test cannot isolate identity drift")
				}
			},
		},
		{
			name: "digest drift with stable identity",
			mutate: func(t *testing.T, targetPath string, before os.FileInfo) {
				file, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_TRUNC, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write([]byte("export const BETA_ = 1;")); err != nil {
					file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				after, err := os.Stat(targetPath)
				if err != nil {
					t.Fatal(err)
				}
				if !os.SameFile(before, after) {
					t.Fatal("in-place rewrite changed file identity; test cannot isolate digest drift")
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repoRoot := t.TempDir()
			packageDir := "packages/alpha"
			packageRoot := filepath.Join(repoRoot, filepath.FromSlash(packageDir))
			if err := os.MkdirAll(packageRoot, 0o755); err != nil {
				t.Fatal(err)
			}
			targetPath := filepath.Join(packageRoot, "real.ts")
			if err := os.WriteFile(targetPath, originalContent, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, alias := range []string{"one.ts", "two.ts", "three.ts"} {
				if err := os.Symlink("real.ts", filepath.Join(packageRoot, alias)); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			scan := newScanCache(repoRoot, maxAggregateScanBytes)
			if scan.initErr != nil {
				t.Fatal(scan.initErr)
			}
			t.Cleanup(func() {
				if err := scan.root.Close(); err != nil {
					t.Errorf("close scan root: %v", err)
				}
			})
			pinnedRoot, err := os.OpenRoot(packageRoot)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := pinnedRoot.Close(); err != nil {
					t.Errorf("close pinned package root: %v", err)
				}
			})
			pkg := packageSnapshot{dir: packageDir, root: pinnedRoot}

			runtimeExports, _, err := scan.collectSourceExports(packageDir+"/one.ts", pkg, "first alias")
			if err != nil {
				t.Fatal(err)
			}
			assertStringSlice(t, runtimeExports, []string{"ALPHA"})
			runtimeExports, _, err = scan.collectSourceExports(packageDir+"/two.ts", pkg, "stable second alias")
			if err != nil {
				t.Fatalf("stable alias reuse: %v", err)
			}
			assertStringSlice(t, runtimeExports, []string{"ALPHA"})

			before, err := os.Stat(targetPath)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(t, targetPath, before)
			_, _, err = scan.collectSourceExports(packageDir+"/three.ts", pkg, "changed third alias")
			if err == nil || !strings.Contains(err.Error(), "canonical source changed identity or content during scan") {
				t.Fatalf("collectSourceExports() error=%v, want cross-alias canonical drift rejection", err)
			}
		})
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

	input := publicAPIManifest()
	second := map[string]any{}
	for key, value := range input["entries"].([]any)[0].(map[string]any) {
		second[key] = value
	}
	second["packageManifestPath"] = "packages/beta/package.json"
	input["entries"] = append(input["entries"].([]any), second)
	_, exitCode, err := Verify(input, Options{RepoRoot: repoRoot})
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "duplicate referenced package name @example/alpha") {
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
		"export const a = {x: 1, b: 2}, c = [\"x\", \"y\"];",
		"export let d = makeValue({left: \"x\", right: \"y\"});",
		"export const ordinaryCall = make(\"x\", \"y\");",
		"export const isSmall = (limit < 10), fallback = 1;",
	}, "\n")

	runtimeExports, typeExports, err := CollectExports(source)
	if err != nil {
		t.Fatalf("collect exports: %v", err)
	}
	assertStringSlice(t, runtimeExports, []string{"a", "c", "d", "fallback", "isSmall", "ordinaryCall"})
	assertStringSlice(t, typeExports, []string{})
}

func TestCollectExportsRejectsRegexLiteralReturnedByArrowInitializer(t *testing.T) {
	_, _, err := CollectExports("export const matcher = () => /,/, next = 1;")
	if err == nil || !strings.Contains(err.Error(), "slash tokens outside comments") {
		t.Fatalf("CollectExports() error=%v, want fail-closed regex rejection", err)
	}
}

func TestCollectExportsFindsMultipleTopLevelExportsOnOneLine(t *testing.T) {
	runtimeExports, typeExports, err := CollectExports("export const A = 1; export const B = 2;")
	if err != nil {
		t.Fatalf("CollectExports() error = %v", err)
	}
	assertStringSlice(t, runtimeExports, []string{"A", "B"})
	assertStringSlice(t, typeExports, []string{})
}

func TestCollectExportsRecognizesAllLineCommentTerminators(t *testing.T) {
	for _, source := range []string{
		"// comment terminated by CR\rexport const Public = 3;",
		"// comment terminated by LS\u2028export const Public = 3;",
		"// comment terminated by PS\u2029export const Public = 3;",
	} {
		runtimeExports, typeExports, err := CollectExports(source)
		if err != nil {
			t.Fatalf("CollectExports() error = %v", err)
		}
		assertStringSlice(t, runtimeExports, []string{"Public"})
		assertStringSlice(t, typeExports, []string{})
	}
}

func TestCollectExportsPreservesStatementOffsetsAcrossMaskedLiterals(t *testing.T) {
	source := "export const FIRST = \"\u00e9; } export\"; export const SECOND = `; } export`; export type Third = { value: string };"
	runtimeExports, typeExports, err := CollectExports(source)
	if err != nil {
		t.Fatalf("CollectExports() error = %v", err)
	}
	assertStringSlice(t, runtimeExports, []string{"FIRST", "SECOND"})
	assertStringSlice(t, typeExports, []string{"Third"})
}

func TestVerifyTypeScriptPackagePublicAPIFailsClosedOnAmbiguousSourceGrammar(t *testing.T) {
	repoRoot := writeTypeScriptPackageFixture(t)
	sourcePath := filepath.Join(repoRoot, "packages", "alpha", "src", "index.ts")
	if err := os.WriteFile(sourcePath, []byte("const ratio = 1 / /\\{/.test(\"{\") ? 1 : 2;\nexport const Public = 3;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	input := publicAPIManifest()
	entry := input["entries"].([]any)[0].(map[string]any)
	entry["runtimeExports"] = []any{}
	entry["typeExports"] = []any{}

	_, exitCode, err := Verify(input, Options{RepoRoot: repoRoot})
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "unsupported TypeScript public API source grammar") {
		t.Fatalf("Verify() exitCode=%d error=%v, want fail-closed grammar rejection", exitCode, err)
	}
}

func TestCollectExportsRejectsLexicallyAmbiguousOrOutOfGrammarSources(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{name: "division and regex", source: "const ratio = 1 / /\\{/.test(\"{\") ? 1 : 2; export const Public = 3;"},
		{name: "unicode code identifier", source: "const \u03c0 = 1; export const Public = 3;"},
		{name: "template interpolation", source: "const value = `prefix ${1}`; export const Public = 3;"},
		{name: "escaped code identifier", source: "const \\u0061 = 1; export const Public = 3;"},
		{name: "top-level angle syntax", source: "export const values: Array<string> = [];"},
		{name: "unterminated block comment", source: "/* hidden export const Ghost = 1;"},
		{name: "unbalanced delimiter", source: "if (true) { export const Nested = 1;"},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			if _, _, err := CollectExports(item.source); err == nil || !strings.Contains(err.Error(), "unsupported TypeScript public API source grammar") {
				t.Fatalf("CollectExports() error=%v, want fail-closed grammar rejection", err)
			}
		})
	}
}

func TestCollectExportsRejectsNamedReexportAliasedAsDefault(t *testing.T) {
	_, _, err := CollectExports(`export { PublicThing as default } from "./thing.js";`)
	if err == nil || !strings.Contains(err.Error(), "default alias") {
		t.Fatalf("CollectExports() error=%v, want default alias rejection", err)
	}
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
	if _, _, err := scan.readFile("oversized.ts", "fixture source", maxSourceFileBytes); err == nil || !strings.Contains(err.Error(), "8 MiB") {
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
		"packageName":         "@example/alpha",
		"packageManifestPath": "packages/alpha/package.json",
		"exportKey":           "./secondary",
		"runtimeExports":      []any{"VALUE", "makeThing"},
		"typeExports":         []any{"Mode", "Thing"},
		"deniedExportKeys":    []any{"./internal"},
		"exportConditions": []any{
			map[string]any{"condition": "import", "path": "./src/index.ts", "sourcePath": "packages/alpha/src/index.ts"},
			map[string]any{"condition": "types", "path": "./src/index.ts", "sourcePath": "packages/alpha/src/index.ts"},
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
	if _, _, err := scan.readFile("first.ts", "first source", maxSourceFileBytes); err != nil {
		t.Fatalf("read first source: %v", err)
	}
	if _, _, err := scan.readFile("second.ts", "second source", maxSourceFileBytes); err == nil || !strings.Contains(err.Error(), "aggregate file-read limit") {
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
	if _, _, _, _, err := readPackageManifest(newScanCache(resolvedRoot, maxAggregateScanBytes), "package.json"); err == nil || !strings.Contains(err.Error(), "256 KiB") {
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
}

func TestVerifyEmptyManifestDoesNotRequireAConventionalPackagesDirectory(t *testing.T) {
	repoRoot := t.TempDir()
	input := map[string]any{
		"schemaVersion":   json.Number("1"),
		"machineContract": defaultMachineContract,
		"entries":         []any{},
	}
	output, exitCode, err := Verify(input, Options{RepoRoot: repoRoot})
	if err != nil || exitCode != 0 || output["entryCount"] != 0 {
		t.Fatalf("Verify(empty) output=%#v exitCode=%d error=%v", output, exitCode, err)
	}
}

func TestVerifyCollectsMultipleSameLineExportsThroughFilesystemBoundary(t *testing.T) {
	repoRoot := writeTypeScriptPackageFixture(t)
	sourcePath := filepath.Join(repoRoot, "packages", "alpha", "src", "index.ts")
	if err := os.WriteFile(sourcePath, []byte("export const A = 1; export const B = 2;"), 0o600); err != nil {
		t.Fatal(err)
	}
	input := publicAPIManifest()
	entry := input["entries"].([]any)[0].(map[string]any)
	entry["runtimeExports"] = []any{"A", "B"}
	entry["typeExports"] = []any{}
	output, exitCode, err := Verify(input, Options{RepoRoot: repoRoot})
	if err != nil || exitCode != 0 {
		t.Fatalf("Verify() output=%#v exitCode=%d error=%v", output, exitCode, err)
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
				"packageName":         "@example/alpha",
				"packageManifestPath": "packages/alpha/package.json",
				"exportKey":           ".",
				"runtimeExports":      []any{"VALUE", "makeThing"},
				"typeExports":         []any{"Mode", "Thing"},
				"deniedExportKeys":    []any{"./internal"},
				"exportConditions": []any{
					map[string]any{"condition": "import", "path": "./src/index.ts", "sourcePath": "packages/alpha/src/index.ts"},
					map[string]any{"condition": "types", "path": "./src/index.ts", "sourcePath": "packages/alpha/src/index.ts"},
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
