package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestVisualInventoryIsTheExactViewEngineSchemeWidthProduct(t *testing.T) {
	references := expectedVisualReferences()
	if len(references) != 169 || len(visualViews) != 14 {
		t.Fatalf("visual inventory has %d references over %d views, want 169 over 14", len(references), len(visualViews))
	}
	ids := map[string]struct{}{}
	perEngine := map[string]int{}
	for index, reference := range references {
		if index > 0 && references[index-1].id() >= reference.id() {
			t.Fatal("visual inventory is not sorted by ID")
		}
		ids[reference.id()] = struct{}{}
		perEngine[reference.Engine]++
	}
	if len(ids) != 169 || perEngine["chromium"] != 57 || perEngine["firefox"] != 56 || perEngine["webkit"] != 56 {
		t.Fatalf("visual inventory engine split = %v", perEngine)
	}
	if _, ok := ids["chromium/readme-scene.light.1440"]; !ok {
		t.Fatal("visual inventory lacks the README scene ID")
	}
	tests := expectedVisualProjectTests()
	if len(tests["chromium"]) != 64 || len(tests["firefox"]) != 63 || len(tests["webkit"]) != 63 {
		t.Fatalf("visual project test sets = %d/%d/%d", len(tests["chromium"]), len(tests["firefox"]), len(tests["webkit"]))
	}
	for _, engine := range visualEngines {
		if !slices.Contains(tests[engine], "tests/visual/font-faces.spec.mjs::font-faces.spec.mjs > each product font stack draws its intended face") {
			t.Fatalf("%s must run the font-face check", engine)
		}
	}
	if !slices.Contains(tests["chromium"], "tests/visual/readme-scene.spec.mjs::readme-scene.spec.mjs > readme-scene light 1440x960") ||
		slices.ContainsFunc(tests["firefox"], func(id string) bool { return strings.Contains(id, "readme-scene") }) {
		t.Fatal("the README scene must be a Chromium-only comparison")
	}
}

// The committed references are digests bound to the recorded environment; no
// image file exists below the visual test directory.
func TestCommittedVisualReferencesAreDigestsBoundToTheRecordedEnvironment(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := verifyVisualReferences(root)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := loadVisualEnvironment(root)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Count != 169 || inventory.EnvironmentID != environment.EnvironmentID {
		t.Fatalf("committed inventory = %+v, environment = %s", inventory, environment.EnvironmentID)
	}
	err = filepath.WalkDir(filepath.Join(root, "tests", "visual"), func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(current), ".png") {
			t.Errorf("image file %s is stored below tests/visual; references are digests only", current)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// copyVisualRecords copies the committed visual records into a disposable root
// so each mutant changes only its copy.
func copyVisualRecords(t *testing.T) string {
	t.Helper()
	source, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "tests", "visual"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{visualEnvironmentPath, visualReferencesPath, visualFontConfigPath} {
		content, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(relative)), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func editJSON(t *testing.T, root, relative string, mutate func(map[string]any)) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(relative))
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	record := value.(map[string]any)
	mutate(record)
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

func referenceEntry(record map[string]any, id string) map[string]any {
	for _, raw := range record["references"].([]any) {
		entry := raw.(map[string]any)
		if entry["id"] == id {
			return entry
		}
	}
	panic("reference entry " + id + " is missing")
}

func TestVisualReferenceInventoryRefusesEveryIntegrityMutant(t *testing.T) {
	view := "chromium/static-source-cards.light.320"
	readme := "chromium/readme-scene.light.1440"
	cases := []struct {
		name   string
		want   string
		mutate func(record map[string]any)
		file   string
	}{
		{"malformed hash", "lowercase sha256", func(record map[string]any) {
			entry := referenceEntry(record, view)
			entry["rgbaSHA256"] = strings.ToUpper(entry["rgbaSHA256"].(string))
		}, visualReferencesPath},
		{"short hash", "lowercase sha256", func(record map[string]any) {
			entry := referenceEntry(record, view)
			entry["rgbaSHA256"] = entry["rgbaSHA256"].(string)[:63]
		}, visualReferencesPath},
		{"missing ID", "must list all 169 expected references", func(record map[string]any) {
			entries := record["references"].([]any)
			record["references"] = append(entries[:5:5], entries[6:]...)
		}, visualReferencesPath},
		{"extra ID", "outside the expected inventory", func(record map[string]any) {
			extra := map[string]any{"height": json.Number("900"), "id": "chromium/static-extra.light.320", "rgbaSHA256": strings.Repeat("a", 64), "width": json.Number("320")}
			record["references"] = append(record["references"].([]any), extra)
		}, visualReferencesPath},
		{"duplicate ID", "more than once", func(record map[string]any) {
			entries := record["references"].([]any)
			record["references"] = append(entries[:2:2], append([]any{entries[1]}, entries[2:]...)...)
		}, visualReferencesPath},
		{"reordered inventory", "sorted by ID", func(record map[string]any) {
			entries := record["references"].([]any)
			entries[3], entries[4] = entries[4], entries[3]
		}, visualReferencesPath},
		{"width other than the view width", "320 CSS pixels wide", func(record map[string]any) {
			referenceEntry(record, view)["width"] = json.Number("321")
		}, visualReferencesPath},
		{"height above the clip", "1 to 2400 tall", func(record map[string]any) {
			referenceEntry(record, view)["height"] = json.Number("2401")
		}, visualReferencesPath},
		{"README scene with other dimensions", "must be 1440x960", func(record map[string]any) {
			referenceEntry(record, readme)["height"] = json.Number("900")
		}, visualReferencesPath},
		{"unowned entry key", "exactly {height, id, rgbaSHA256, width}", func(record map[string]any) {
			referenceEntry(record, view)["path"] = "tests/visual/references/x.png"
		}, visualReferencesPath},
		{"environmentId mismatch", "environmentId does not match", func(record map[string]any) {
			record["environmentId"] = "sha256:" + strings.Repeat("0", 64)
		}, visualReferencesPath},
		{"changed environment field", "environmentId does not match", func(record map[string]any) {
			record["observed"].(map[string]any)["packages"].(map[string]any)["fontconfig"] = "2.15.0-1.1ubuntu3"
		}, visualEnvironmentPath},
		{"changed fontconfig digest", "environmentId does not match", func(record map[string]any) {
			record["observed"].(map[string]any)["fontConfig"] = "sha256:" + strings.Repeat("1", 64)
		}, visualEnvironmentPath},
		{"emulated reference environment", "must not be emulated", func(record map[string]any) {
			record["observed"].(map[string]any)["emulation"] = "translator-mapped"
		}, visualEnvironmentPath},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			root := copyVisualRecords(t)
			if _, err := verifyVisualReferences(root); err != nil {
				t.Fatalf("unmutated copy was refused: %v", err)
			}
			editJSON(t, root, item.file, item.mutate)
			_, err := verifyVisualReferences(root)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("mutant error = %v, want %q", err, item.want)
			}
		})
	}
}

// visualAdmissionRun builds a complete reference-environment run directory
// with synthetic captures of the admitted dimensions, its observed
// environment and a candidate inventory recomputed by the digest owner.
func visualAdmissionRun(t *testing.T, root string) string {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("reference admission recomputes digests with node")
	}
	run := t.TempDir()
	for index, reference := range expectedVisualReferences() {
		width, height := reference.Width, 3
		if reference.isReadmeScene() {
			height = readmeSceneHeight
		}
		picture := image.NewNRGBA(image.Rect(0, 0, width, height))
		picture.Set(index%width, 0, color.NRGBA{R: uint8(index), G: 7, B: 9, A: 255})
		target := filepath.Join(run, visualCaptureRunDirectory, filepath.FromSlash(reference.id()+".png"))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		var encoded bytes.Buffer
		if err := png.Encode(&encoded, picture); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, encoded.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	environment, err := loadVisualEnvironment(root)
	if err != nil {
		t.Fatal(err)
	}
	observed := map[string]any{
		"cpu":             map[string]any{"avx2": nil, "avx512f": nil, "features": "fp asimd", "hypervisor": nil, "model": "part 0xd49", "vendor": "implementer 0x41"},
		"divergentFields": []any{},
	}
	for key, value := range environment.Observed {
		observed[key] = value
	}
	writeRunJSON(t, filepath.Join(run, visualObservedRunFile), observed)
	recomputed, err := recomputeCaptureDigests(root, filepath.Join(run, visualCaptureRunDirectory))
	if err != nil {
		t.Fatal(err)
	}
	references := []any{}
	for _, entry := range recomputed {
		references = append(references, map[string]any{"height": entry.Height, "id": entry.ID, "rgbaSHA256": entry.RGBASHA256, "width": entry.Width})
	}
	writeRunJSON(t, filepath.Join(run, visualCandidateRunFile), map[string]any{"clipHeight": visualClipHeight, "environmentId": environment.EnvironmentID, "kind": "proofkit.browser-visual-references", "references": references, "schemaVersion": 1})
	return run
}

func writeRunJSON(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Reference admission accepts only a complete, stable reference-environment
// run, recomputes every digest from the PNG files and never trusts the run's
// JSON for a digest.
func TestVisualReferenceAdmissionFromRunRefusesEveryUnadmissibleRun(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	run := visualAdmissionRun(t, root)
	encoded, err := buildVisualReferenceInventoryFromRun(root, run)
	if err != nil {
		t.Fatalf("complete reference-environment run was refused: %v", err)
	}
	admitted := copyVisualRecords(t)
	if err := os.WriteFile(filepath.Join(admitted, filepath.FromSlash(visualReferencesPath)), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if inventory, err := verifyVisualReferences(admitted); err != nil || inventory.Count != 169 {
		t.Fatalf("admitted inventory = %+v, %v", inventory, err)
	}
	captureOf := func(run, id string) string {
		return filepath.Join(run, visualCaptureRunDirectory, filepath.FromSlash(id+".png"))
	}
	cases := []struct {
		name   string
		want   string
		mutate func(t *testing.T, run string)
	}{
		{"divergent observed environment", "observed another environment", func(t *testing.T, run string) {
			editJSONFile(t, filepath.Join(run, visualObservedRunFile), func(record map[string]any) {
				record["architecture"] = "x86_64"
				record["divergentFields"] = []any{"architecture"}
			})
		}},
		{"claimed divergence", "lists divergent fields although every compared field equals the recorded environment", func(t *testing.T, run string) {
			editJSONFile(t, filepath.Join(run, visualObservedRunFile), func(record map[string]any) {
				record["divergentFields"] = []any{"fontConfig"}
			})
		}},
		{"missing observed environment", "observed environment", func(t *testing.T, run string) {
			if err := os.Remove(filepath.Join(run, visualObservedRunFile)); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing capture", "missing 1 of 169 captures", func(t *testing.T, run string) {
			if err := os.Remove(captureOf(run, "webkit/workspace-diff.dark.320")); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra capture", "unexpected file", func(t *testing.T, run string) {
			content, err := os.ReadFile(captureOf(run, "webkit/workspace-diff.dark.320"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(run, visualCaptureRunDirectory, "webkit", "extra.dark.320.png"), content, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"unstable capture", "unstable captures", func(t *testing.T, run string) {
			if err := os.MkdirAll(filepath.Join(run, visualUnstableRunDirectory), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"corrupted PNG", "recompute visual capture digests", func(t *testing.T, run string) {
			target := captureOf(run, "firefox/static-coverage-table.dark.1440")
			content, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			content[len(content)/2] ^= 0xff
			if err := os.WriteFile(target, content, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"replaced PNG", "no longer matches", func(t *testing.T, run string) {
			if err := copyFile(captureOf(run, "firefox/static-coverage-table.light.1440"), captureOf(run, "firefox/static-coverage-table.dark.1440")); err != nil {
				t.Fatal(err)
			}
		}},
		{"capture with another width", "1440 CSS pixels wide", func(t *testing.T, run string) {
			if err := copyFile(captureOf(run, "firefox/static-coverage-table.light.320"), captureOf(run, "firefox/static-coverage-table.dark.1440")); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlinked capture", "symlink", func(t *testing.T, run string) {
			target := captureOf(run, "chromium/workspace-coverage.light.320")
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(captureOf(run, "chromium/workspace-coverage.dark.320"), target); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			mutated := t.TempDir()
			if err := os.CopyFS(mutated, os.DirFS(run)); err != nil {
				t.Fatal(err)
			}
			item.mutate(t, mutated)
			if _, err := buildVisualReferenceInventoryFromRun(root, mutated); err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("admission error = %v, want %q", err, item.want)
			}
		})
	}
}

func editJSONFile(t *testing.T, target string, mutate func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	record := value.(map[string]any)
	mutate(record)
	writeRunJSON(t, target, record)
}

func copyFile(source, target string) error {
	content, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(target, content, 0o644)
}

func TestVisualEnvironmentBindsThePinnedPlaywrightToolchain(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	environment, err := loadVisualEnvironment(root)
	if err != nil {
		t.Fatal(err)
	}
	lockRaw, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(lockRaw, &lock); err != nil {
		t.Fatal(err)
	}
	version := lock.Packages["node_modules/@playwright/test"].Version
	if version == "" || lock.Packages["node_modules/playwright-core"].Version != version {
		t.Fatalf("package-lock.json must pin @playwright/test and playwright-core to one version")
	}
	image := environment.Raw["image"].(map[string]any)
	if image["tag"] != "v"+version+"-noble" || image["platform"] != "linux/arm64" {
		t.Fatalf("reference image tag/platform = %v/%v, want v%s-noble on linux/arm64", image["tag"], image["platform"], version)
	}
	docker := environment.Observed["dockerImage"].(map[string]any)
	if docker["dockerImageName"] != image["name"].(string)+":"+image["tag"].(string) || docker["driverVersion"] != version {
		t.Fatalf("observed image marker %v does not name the recorded image", docker)
	}
	// The engine revisions and launched versions equal the pinned registry.
	browsersRaw, err := os.ReadFile(filepath.Join(root, "node_modules", "playwright-core", "browsers.json"))
	if err != nil {
		t.Fatalf("read the installed playwright-core browsers.json (run npm ci first): %v", err)
	}
	var browsers struct {
		Browsers []struct {
			Name           string `json:"name"`
			Revision       string `json:"revision"`
			BrowserVersion string `json:"browserVersion"`
		} `json:"browsers"`
	}
	if err := json.Unmarshal(browsersRaw, &browsers); err != nil {
		t.Fatal(err)
	}
	// The compared font environment is the committed fontconfig file.
	fontConfig, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(visualFontConfigPath)))
	if err != nil {
		t.Fatal(err)
	}
	fontSum := sha256.Sum256(fontConfig)
	if environment.Observed["fontConfig"] != "sha256:"+hex.EncodeToString(fontSum[:]) {
		t.Fatalf("environment fontConfig=%v does not bind %s", environment.Observed["fontConfig"], visualFontConfigPath)
	}
	// Each recorded fc-match result is the match of its whole family name.
	fontMatches, _ := environment.Observed["fontMatches"].(map[string]any)
	wantMatches := map[string]string{"sans-serif": "Liberation Sans", "system-ui": "Liberation Sans", "serif": "Liberation Serif", "monospace": "Liberation Mono", "ui-monospace": "Liberation Mono"}
	if len(fontMatches) != len(wantMatches) {
		t.Fatalf("recorded fc-match families = %v, want %v", fontMatches, wantMatches)
	}
	for family, face := range wantMatches {
		match, _ := fontMatches[family].(string)
		if !strings.Contains(match, "\""+face+"\"") {
			t.Fatalf("recorded fc-match for %s is %q, want %s", family, match, face)
		}
	}
	engines := environment.Observed["engines"].(map[string]any)
	for _, name := range visualEngines {
		found := false
		for _, browser := range browsers.Browsers {
			if browser.Name == name {
				found = true
				if engines[name] != browser.Revision || environment.BrowserVersions[name] != browser.BrowserVersion {
					t.Fatalf("%s revision/version = %v/%s, want browsers.json %s/%s", name, engines[name], environment.BrowserVersions[name], browser.Revision, browser.BrowserVersion)
				}
			}
		}
		if !found {
			t.Fatalf("browsers.json has no %s engine", name)
		}
	}
}

func TestVisualReferencesStayOutsideThePackage(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Files []string `json:"files"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	candidates := []string{}
	err = filepath.WalkDir(filepath.Join(root, "tests", "visual"), func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		relative, err := filepath.Rel(root, current)
		candidates = append(candidates, filepath.ToSlash(relative))
		return err
	})
	if err != nil || !slices.Contains(candidates, visualReferencesPath) || !slices.Contains(candidates, visualFontConfigPath) {
		t.Fatalf("visual test files = %v, %v", candidates, err)
	}
	for _, pattern := range manifest.Files {
		for _, candidate := range candidates {
			prefix := strings.TrimSuffix(strings.TrimSuffix(pattern, "/**/*"), "/**")
			matched, err := path.Match(pattern, candidate)
			if err != nil {
				t.Fatal(err)
			}
			if matched || pattern == candidate || strings.HasPrefix(candidate, prefix+"/") {
				t.Fatalf("package files pattern %q includes visual gate material %s", pattern, candidate)
			}
		}
	}
}

func TestBrowserVisualScriptIsSeparateFromThePackageGate(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Scripts["browser:visual"] != "go run ./internal/tools/browserproofverify --manifest scripts/browser-visual-proof-inputs.v1.json --run" {
		t.Fatalf("browser:visual must delegate to the single Go orchestrator with the visual manifest, got %q", manifest.Scripts["browser:visual"])
	}
	for name, script := range manifest.Scripts {
		if name != "browser:visual" && strings.Contains(script, "browser:visual") || strings.Contains(script, visualProofManifestPath) && name != "browser:visual" {
			t.Fatalf("script %q composes the visual gate; it must stay outside npm run check", name)
		}
	}
	for _, hook := range []string{"prebrowser:visual", "postbrowser:visual"} {
		if _, exists := manifest.Scripts[hook]; exists {
			t.Fatalf("browser:visual must not have lifecycle hook %q", hook)
		}
	}
}
