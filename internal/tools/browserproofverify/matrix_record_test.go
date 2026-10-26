package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func matrixKind(t *testing.T, family string) proofKind {
	t.Helper()
	for _, kind := range proofKinds {
		if kind.Family == family {
			return kind
		}
	}
	t.Fatalf("no matrix proof kind for family %q", family)
	return proofKind{}
}

// matrixRecordFixture builds the passed record a matrix writer would produce
// for root in the reference environment, recomputing every content-bound field.
func matrixRecordFixture(t *testing.T, root string, kind proofKind, resolution proofInputResolution) map[string]any {
	t.Helper()
	assets := make([]any, 0, len(resolution.InputPaths))
	for _, path := range resolution.InputPaths {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		assets = append(assets, map[string]any{"path": path, "sha256": hex.EncodeToString(sum[:])})
	}
	inputResolution := map[string]any{"serverTarget": resolution.ServerTarget, "writerPath": resolution.WriterPath}
	encoded, err := stablejson.MarshalLayout(map[string]any{"assets": assets, "inputResolution": inputResolution}, stablejson.LayoutCompact)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := loadVisualEnvironment(root)
	if err != nil {
		t.Fatal(err)
	}
	observed := map[string]any{"cpu": map[string]any{"avx2": nil, "avx512f": nil, "features": "fp asimd sve sve2", "hypervisor": nil, "model": "part 0xd49", "vendor": "implementer 0x41"}}
	for key, value := range environment.Observed {
		observed[key] = value
	}
	nonClaims := make([]any, len(matrixProofNonClaims))
	for index, nonClaim := range matrixProofNonClaims {
		nonClaims[index] = nonClaim
	}
	argv := make([]any, len(matrixCommandArgv))
	for index, value := range matrixCommandArgv {
		argv[index] = value
	}
	engines, projects := []any{}, []any{}
	expected := expectedMatrixProjectTests(kind.Family)
	for _, name := range visualEngines {
		ids := make([]any, len(expected[name]))
		for index, id := range expected[name] {
			ids[index] = id
		}
		count := json.Number(fmtInt(len(ids)))
		engines = append(engines, map[string]any{"name": name, "version": environment.BrowserVersions[name]})
		projects = append(projects, map[string]any{"browserName": name, "browserVersion": environment.BrowserVersions[name], "executedTestCount": count, "name": name, "passedTestCount": count, "testIds": ids})
	}
	return map[string]any{
		"assets":          assets,
		"command":         map[string]any{"argv": argv, "exitCode": json.Number("0"), "inputMode": "materialized_snapshot", "runner": "node"},
		"divergentFields": []any{}, "engines": engines, "family": kind.Family,
		"inputDigest": digest.SHA256TextRef(strings.TrimSuffix(string(encoded), "\n")), "inputResolution": inputResolution,
		"nonClaims": nonClaims, "observedEnvironment": observed, "projects": projects,
		"proofKind":            matrixRecordKind,
		"referenceEnvironment": map[string]any{"environmentId": environment.EnvironmentID},
		"schemaVersion":        json.Number("1"), "sourceRevision": "abc123", "sourceTreeState": "dirty", "state": "passed",
	}
}

func repositoryMatrixResolution(t *testing.T, kind proofKind) (string, proofInputResolution) {
	t.Helper()
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadProofInputManifest(root, kind)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := resolveProofInputs(root, manifest, kind)
	if err != nil {
		t.Fatal(err)
	}
	return root, resolution
}

func TestMatrixRequiresChildPaintAndMobileIdentityControls(t *testing.T) {
	for _, family := range []string{"static", "workspace"} {
		tests := expectedMatrixProjectTests(family)
		required := []string{
			"tests/matrix/" + family + "/controls.spec.mjs::controls.spec.mjs > contrast refuses opaque child paint and preserves transparent text wrappers",
			"tests/matrix/" + family + "/controls.spec.mjs::controls.spec.mjs > contrast checks every text owner's threshold in either DOM order",
			"tests/matrix/" + family + "/controls.spec.mjs::controls.spec.mjs > security refuses an uncaught page error",
		}
		if family == "workspace" {
			required = append(required, "tests/matrix/workspace/tasks.spec.mjs::tasks.spec.mjs > a reader can use view controls below a tall mobile product identity")
		}
		for _, engine := range visualEngines {
			for _, id := range required {
				if !slices.Contains(tests[engine], id) {
					t.Fatalf("%s %s is missing mandatory test %s", family, engine, id)
				}
			}
		}
	}
}

// The matrix is the fourteen inventory views in each engine, color scheme and
// mode, plus the two workspace dialogs in the three narrow modes: 456 cells.
func TestMatrixInventoryIsTheExactCellProduct(t *testing.T) {
	staticCells, workspaceCells := expectedMatrixCellTitles("static"), expectedMatrixCellTitles("workspace")
	if len(staticCells) != 10*2*5 || len(workspaceCells) != 4*2*5+2*2*3 {
		t.Fatalf("matrix cells per engine: static %d, workspace %d", len(staticCells), len(workspaceCells))
	}
	if total := len(visualEngines) * (len(staticCells) + len(workspaceCells)); total != 456 {
		t.Fatalf("matrix cells = %d, want 456", total)
	}
	if len(matrixFamilyViews("static"))+len(matrixFamilyViews("workspace")) != len(visualViews) {
		t.Fatal("the matrix views must be exactly the visual inventory views")
	}
	for _, family := range []string{"static", "workspace"} {
		tests := expectedMatrixProjectTests(family)
		for _, engine := range visualEngines {
			want := len(expectedMatrixCellTitles(family)) + len(matrixControlTitles) + len(matrixFamilyControlTitles[family]) + len(matrixTaskTitles[family])
			if family == "static" && engine == "firefox" {
				want++
			}
			if len(tests[engine]) != want || !slices.IsSorted(tests[engine]) || len(slices.Compact(slices.Clone(tests[engine]))) != want {
				t.Fatalf("%s %s expected tests = %d, want %d sorted unique", family, engine, len(tests[engine]), want)
			}
		}
		if !slices.Contains(tests["chromium"], "tests/matrix/"+family+"/cells.spec.mjs::cells.spec.mjs > 720-dsf-2 > "+matrixFamilyViews(family)[0]+" dark") {
			t.Fatalf("%s lacks its zoom cell identity", family)
		}
	}
	firefox := expectedMatrixProjectTests("static")["firefox"]
	if !slices.Contains(firefox, "tests/matrix/static/firefox-site-icons.spec.mjs::firefox-site-icons.spec.mjs > "+matrixFirefoxSiteIconTitle) ||
		slices.ContainsFunc(expectedMatrixProjectTests("static")["webkit"], func(id string) bool { return strings.Contains(id, "firefox-site-icons") }) {
		t.Fatal("the site-icon control must run only in Firefox")
	}
	if !slices.Contains(expectedMatrixProjectTests("workspace")["webkit"], "tests/matrix/workspace/cells.spec.mjs::cells.spec.mjs > 320-root-200 > workspace-inspector-dialog light") ||
		slices.Contains(expectedMatrixProjectTests("workspace")["webkit"], "tests/matrix/workspace/cells.spec.mjs::cells.spec.mjs > 1440 > workspace-inspector-dialog light") {
		t.Fatal("the dialog cells must exist exactly in the narrow modes")
	}
}

func TestMatrixRecordAdmitsOnlyAPassedRecordOfItsFamily(t *testing.T) {
	for _, family := range []string{"static", "workspace"} {
		kind := matrixKind(t, family)
		root, resolution := repositoryMatrixResolution(t, kind)
		if err := verifyMatrixRecord(root, kind, matrixRecordFixture(t, root, kind, resolution), resolution, "abc123", "dirty"); err != nil {
			t.Fatalf("%s matrix record was refused: %v", family, err)
		}
		divergent := matrixRecordFixture(t, root, kind, resolution)
		divergent["observedEnvironment"].(map[string]any)["architecture"] = "arm64"
		divergent["divergentFields"] = []any{"architecture"}
		for index := range divergent["projects"].([]any) {
			divergent["projects"].([]any)[index].(map[string]any)["browserVersion"] = "local"
			divergent["engines"].([]any)[index].(map[string]any)["version"] = "local"
		}
		if err := verifyMatrixRecord(root, kind, divergent, resolution, "abc123", "dirty"); err != nil {
			t.Fatalf("%s matrix record of another environment that lists its divergence was refused: %v", family, err)
		}
		other := "workspace"
		if family == "workspace" {
			other = "static"
		}
		cases := []struct {
			name   string
			mutate func(map[string]any)
		}{
			{"other family", func(record map[string]any) { record["family"] = other }},
			{"unverified state", func(record map[string]any) { record["state"] = "unverified" }},
			{"other record kind", func(record map[string]any) { record["proofKind"] = "proofkit.browser-visual-proof" }},
			{"schema version", func(record map[string]any) { record["schemaVersion"] = json.Number("2") }},
			{"source revision", func(record map[string]any) { record["sourceRevision"] = "def456" }},
			{"source tree state", func(record map[string]any) { record["sourceTreeState"] = "clean" }},
			{"weakened non-claims", func(record map[string]any) { record["nonClaims"] = record["nonClaims"].([]any)[1:] }},
			{"unknown key", func(record map[string]any) { record["retries"] = json.Number("1") }},
			{"command argv", func(record map[string]any) {
				record["command"].(map[string]any)["argv"] = []any{"node_modules/@playwright/test/cli.js", "test"}
			}},
			{"failed exit", func(record map[string]any) { record["command"].(map[string]any)["exitCode"] = json.Number("1") }},
			{"command runner", func(record map[string]any) { record["command"].(map[string]any)["runner"] = "bun" }},
			{"command input mode", func(record map[string]any) { record["command"].(map[string]any)["inputMode"] = "mutable_worktree" }},
			{"other environment id", func(record map[string]any) {
				record["referenceEnvironment"].(map[string]any)["environmentId"] = "sha256:" + strings.Repeat("0", 64)
			}},
			{"undeclared divergence", func(record map[string]any) {
				record["observedEnvironment"].(map[string]any)["architecture"] = "x86_64"
			}},
			{"claimed divergence", func(record map[string]any) { record["divergentFields"] = []any{"architecture"} }},
			{"incomplete observed environment", func(record map[string]any) { delete(record["observedEnvironment"].(map[string]any), "fontConfig") }},
			{"reference environment with another engine version", func(record map[string]any) {
				record["projects"].([]any)[1].(map[string]any)["browserVersion"] = "1"
				record["engines"].([]any)[1].(map[string]any)["version"] = "1"
			}},
			{"engine version not from its project", func(record map[string]any) { record["engines"].([]any)[2].(map[string]any)["version"] = "1" }},
			{"project name", func(record map[string]any) { record["projects"].([]any)[0].(map[string]any)["name"] = "chrome" }},
			{"project browser name", func(record map[string]any) { record["projects"].([]any)[0].(map[string]any)["browserName"] = "chrome" }},
			{"project version empty", func(record map[string]any) { record["projects"].([]any)[0].(map[string]any)["browserVersion"] = "" }},
			{"engine name", func(record map[string]any) { record["engines"].([]any)[0].(map[string]any)["name"] = "chrome" }},
			{"engine order", func(record map[string]any) {
				engines := record["engines"].([]any)
				engines[0], engines[1] = engines[1], engines[0]
			}},
			{"project order", func(record map[string]any) {
				projects := record["projects"].([]any)
				projects[0], projects[1] = projects[1], projects[0]
			}},
			{"two engine versions", func(record map[string]any) { record["engines"] = record["engines"].([]any)[:2] }},
			{"test id order", func(record map[string]any) {
				ids := record["projects"].([]any)[0].(map[string]any)["testIds"].([]any)
				ids[0], ids[1] = ids[1], ids[0]
			}},
			{"duplicate test id", func(record map[string]any) {
				ids := record["projects"].([]any)[0].(map[string]any)["testIds"].([]any)
				ids[1] = ids[0]
			}},
			{"wrong executed count", func(record map[string]any) {
				record["projects"].([]any)[0].(map[string]any)["executedTestCount"] = json.Number("1")
			}},
			{"text passed count", func(record map[string]any) { record["projects"].([]any)[0].(map[string]any)["passedTestCount"] = "1" }},
			{"input digest", func(record map[string]any) { record["inputDigest"] = "sha256:" + strings.Repeat("0", 64) }},
			{"input server", func(record map[string]any) {
				record["inputResolution"].(map[string]any)["serverTarget"] = "./internal/tools/other"
			}},
			{"input writer", func(record map[string]any) {
				record["inputResolution"].(map[string]any)["writerPath"] = "scripts/other.mjs"
			}},
			{"asset order", func(record map[string]any) {
				assets := record["assets"].([]any)
				assets[0], assets[1] = assets[1], assets[0]
			}},
			{"asset count", func(record map[string]any) { record["assets"] = record["assets"].([]any)[1:] }},
			{"invalid observed font digest", func(record map[string]any) { record["observedEnvironment"].(map[string]any)["fontConfig"] = "invalid" }},
			{"invalid observed architecture", func(record map[string]any) { record["observedEnvironment"].(map[string]any)["architecture"] = true }},
			{"invalid observed OS", func(record map[string]any) { record["observedEnvironment"].(map[string]any)["os"] = "linux" }},
			{"invalid observed package", func(record map[string]any) {
				record["observedEnvironment"].(map[string]any)["packages"].(map[string]any)["fontconfig"] = true
			}},
			{"invalid CPU flag", func(record map[string]any) {
				record["observedEnvironment"].(map[string]any)["cpu"].(map[string]any)["avx2"] = "false"
			}},
			{"invalid CPU text", func(record map[string]any) {
				record["observedEnvironment"].(map[string]any)["cpu"].(map[string]any)["model"] = true
			}},
			{"missing cell", func(record map[string]any) {
				project := record["projects"].([]any)[0].(map[string]any)
				ids := project["testIds"].([]any)
				project["testIds"], project["executedTestCount"], project["passedTestCount"] = ids[1:], json.Number(fmtInt(len(ids)-1)), json.Number(fmtInt(len(ids)-1))
			}},
			{"extra test", func(record map[string]any) {
				project := record["projects"].([]any)[2].(map[string]any)
				ids := append(slices.Clone(project["testIds"].([]any)), "tests/matrix/"+family+"/zz.spec.mjs::zz.spec.mjs > extra")
				project["testIds"], project["executedTestCount"], project["passedTestCount"] = ids, json.Number(fmtInt(len(ids))), json.Number(fmtInt(len(ids)))
			}},
			{"fewer passed than executed", func(record map[string]any) {
				project := record["projects"].([]any)[1].(map[string]any)
				project["passedTestCount"] = json.Number(fmtInt(len(project["testIds"].([]any)) - 1))
			}},
			{"two engines", func(record map[string]any) { record["projects"] = record["projects"].([]any)[:2] }},
			{"changed asset", func(record map[string]any) {
				record["assets"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64)
			}},
		}
		for _, item := range cases {
			t.Run(family+"/"+item.name, func(t *testing.T) {
				record := matrixRecordFixture(t, root, kind, resolution)
				item.mutate(record)
				if err := verifyMatrixRecord(root, kind, record, resolution, "abc123", "dirty"); err == nil {
					t.Fatal("mutated matrix record was admitted")
				}
			})
		}
	}
}

func TestMatrixRecordRejectsStructuralMutations(t *testing.T) {
	for _, family := range []string{"static", "workspace"} {
		kind := matrixKind(t, family)
		root, resolution := repositoryMatrixResolution(t, kind)
		base := matrixRecordFixture(t, root, kind, resolution)
		if err := verifyMatrixRecord(root, kind, base, resolution, "abc123", "dirty"); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		fresh := func(t *testing.T) map[string]any {
			t.Helper()
			var record map[string]any
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.UseNumber()
			if err := decoder.Decode(&record); err != nil {
				t.Fatal(err)
			}
			return record
		}
		objects := []struct {
			name         string
			keys         []string
			selectObject func(map[string]any) map[string]any
		}{
			{"record", []string{"assets", "command", "divergentFields", "engines", "family", "inputDigest", "inputResolution", "nonClaims", "observedEnvironment", "projects", "proofKind", "referenceEnvironment", "schemaVersion", "sourceRevision", "sourceTreeState", "state"}, func(r map[string]any) map[string]any { return r }},
			{"command", []string{"argv", "exitCode", "inputMode", "runner"}, func(r map[string]any) map[string]any { return r["command"].(map[string]any) }},
			{"reference", []string{"environmentId"}, func(r map[string]any) map[string]any { return r["referenceEnvironment"].(map[string]any) }},
			{"project", []string{"browserName", "browserVersion", "executedTestCount", "name", "passedTestCount", "testIds"}, func(r map[string]any) map[string]any { return r["projects"].([]any)[0].(map[string]any) }},
			{"engine", []string{"name", "version"}, func(r map[string]any) map[string]any { return r["engines"].([]any)[0].(map[string]any) }},
			{"input", []string{"serverTarget", "writerPath"}, func(r map[string]any) map[string]any { return r["inputResolution"].(map[string]any) }},
			{"asset", []string{"path", "sha256"}, func(r map[string]any) map[string]any { return r["assets"].([]any)[0].(map[string]any) }},
		}
		for _, object := range objects {
			for _, key := range append(append([]string{}, object.keys...), "unknown") {
				for _, mode := range []string{"missing", "null"} {
					if key == "unknown" && mode == "missing" {
						continue
					}
					t.Run(family+"/"+object.name+"/"+key+"/"+mode, func(t *testing.T) {
						record := fresh(t)
						fields := object.selectObject(record)
						if mode == "missing" {
							delete(fields, key)
						} else {
							fields[key] = nil
						}
						if err := verifyMatrixRecord(root, kind, record, resolution, "abc123", "dirty"); err == nil {
							t.Fatal("structurally invalid matrix record was admitted")
						}
					})
				}
			}
		}
		if err := verifyMatrixRecord(root, kind, nil, resolution, "abc123", "dirty"); err == nil {
			t.Fatal("null matrix record was admitted")
		}
		// These observation values may be null, but their named fields must exist.
		for _, object := range []struct {
			name         string
			keys         []string
			selectObject func(map[string]any) map[string]any
		}{
			{"environment", []string{"architecture", "cpu", "dockerImage", "emulation", "engines", "fontConfig", "fontMatches", "os", "packages"}, func(r map[string]any) map[string]any { return r["observedEnvironment"].(map[string]any) }},
			{"cpu", []string{"avx2", "avx512f", "features", "hypervisor", "model", "vendor"}, func(r map[string]any) map[string]any {
				return r["observedEnvironment"].(map[string]any)["cpu"].(map[string]any)
			}},
		} {
			for _, key := range append(append([]string{}, object.keys...), "unknown") {
				t.Run(family+"/"+object.name+"/"+key, func(t *testing.T) {
					record := fresh(t)
					fields := object.selectObject(record)
					if key == "unknown" {
						fields[key] = nil
					} else {
						delete(fields, key)
					}
					if err := verifyMatrixRecord(root, kind, record, resolution, "abc123", "dirty"); err == nil {
						t.Fatal("incomplete or extended environment observation was admitted")
					}
				})
			}
		}
	}
}

func TestMatrixRecordReaderRejectsDuplicateKeys(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "record.json"), []byte(`{"family":"static","family":"workspace"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRepositoryJSON(root, "record.json", 1024); err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("strict repository JSON reader must reject duplicate keys, got %v", err)
	}
}

// The site-icon control exists only for the Firefox site-icon preference;
// both matrix kinds admit the reference-environment flag and write only
// passed records.
func TestMatrixProofKindsRequireTheReferenceEnvironmentAndPassedRecords(t *testing.T) {
	for _, family := range []string{"static", "workspace"} {
		kind := matrixKind(t, family)
		if !kind.ReferenceEnvironment || !slices.Equal(kind.States, []string{"passed"}) || kind.RetainRun || kind.isVisual() || !kind.isMatrix() ||
			kind.CommandID != "proofkit.browser-matrix-"+family || kind.RecordPath != "artifacts/proofkit/browser-matrix-"+family+"-proof.json" {
			t.Fatalf("%s matrix proof kind = %+v", family, kind)
		}
		if !slices.Equal(kind.expectedProjectTests()["firefox"], expectedMatrixProjectTests(family)["firefox"]) {
			t.Fatalf("%s matrix report admission must use the family's expected tests", family)
		}
	}
	if runtimeProofKind().ReferenceEnvironment || !visualProofKind().ReferenceEnvironment || runtimeProofKind().expectedProjectTests() != nil {
		t.Fatal("only the visual and matrix kinds observe the reference environment; the runtime kind keeps its equal-set admission")
	}
}

func TestBrowserMatrixScriptsAreSeparateFromThePackageGate(t *testing.T) {
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
	want := map[string]string{
		"browser:matrix":           "npm run browser:matrix:static && npm run browser:matrix:workspace",
		"browser:matrix:static":    "go run ./internal/tools/browserproofverify --manifest scripts/browser-matrix-static-proof-inputs.v1.json --run",
		"browser:matrix:workspace": "go run ./internal/tools/browserproofverify --manifest scripts/browser-matrix-workspace-proof-inputs.v1.json --run",
	}
	for name, script := range want {
		if manifest.Scripts[name] != script {
			t.Fatalf("%s = %q, want %q", name, manifest.Scripts[name], script)
		}
	}
	for name, script := range manifest.Scripts {
		if _, owned := want[name]; owned {
			continue
		}
		if strings.Contains(script, "browser:matrix") || strings.Contains(script, matrixStaticProofManifestPath) || strings.Contains(script, matrixWorkspaceProofManifestPath) {
			t.Fatalf("script %q composes the accessibility matrix; it must stay outside npm run check", name)
		}
	}
	for name := range want {
		for _, hook := range []string{"pre" + name, "post" + name} {
			if _, exists := manifest.Scripts[hook]; exists {
				t.Fatalf("%s must not have lifecycle hook %q", name, hook)
			}
		}
	}
}
