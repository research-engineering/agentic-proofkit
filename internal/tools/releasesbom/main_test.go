package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

func TestCompoundLicenseUsesCycloneDXExpression(t *testing.T) {
	manifest := packageJSON{Name: "@research-engineering/agentic-proofkit", Version: "1.2.3", License: "MIT AND BSD-3-Clause"}
	path := filepath.Join(t.TempDir(), "artifact.txt")
	writeFile(t, path, "artifact")
	files, _, err := releaseFileEvidence(manifest, []string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range append([]cyclonedxComponent{rootComponent(manifest)}, files...) {
		encoded, err := json.Marshal(component)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatal(err)
		}
		licenses := value["licenses"].([]any)
		choice := licenses[0].(map[string]any)
		if choice["expression"] != manifest.License || len(choice) != 1 {
			t.Fatalf("CycloneDX license choice=%v, want only SPDX expression", choice)
		}
	}
}

func TestArtifactSpecificRuntimeEdgesAndExcludedInventory(t *testing.T) {
	source := []goModuleRecord{
		{Path: "example.invalid/runtime", Version: "v1.0.0"},
		{Path: "example.invalid/tool", Version: "v2.0.0"},
	}
	artifacts := []artifactRuntimeInventory{
		{
			BinaryRef: "file:dist/platform/linux-x64/agentic-proofkit",
			Modules:   []goModuleRecord{{Path: "example.invalid/runtime", Version: "v1.0.0"}},
		},
		{
			BinaryRef: "file:dist/platform/darwin-arm64/agentic-proofkit",
			Modules:   nil,
		},
	}

	components, dependencies := projectModuleEvidence(source, artifacts)
	byRef := map[string]cyclonedxComponent{}
	for _, component := range components {
		byRef[component.BOMRef] = component
	}
	runtimeRef := "go-module:example.invalid/runtime@v1.0.0"
	toolRef := "go-module:example.invalid/tool@v2.0.0"
	if byRef[runtimeRef].Scope != "required" {
		t.Fatalf("runtime scope = %q, want required", byRef[runtimeRef].Scope)
	}
	if byRef[toolRef].Scope != "excluded" {
		t.Fatalf("tool scope = %q, want excluded", byRef[toolRef].Scope)
	}
	if !hasProperty(byRef[toolRef], "proofkit:evidence-class", "source_build_inventory") {
		t.Fatalf("tool properties = %#v, want excluded source inventory evidence", byRef[toolRef].Properties)
	}
	dependencyByRef := map[string][]string{}
	for _, dependency := range dependencies {
		dependencyByRef[dependency.Ref] = dependency.DependsOn
	}
	if got := dependencyByRef[artifacts[0].BinaryRef]; !slices.Equal(got, []string{runtimeRef}) {
		t.Fatalf("linux runtime edges = %v, want [%s]", got, runtimeRef)
	}
	if got := dependencyByRef[artifacts[1].BinaryRef]; len(got) != 0 {
		t.Fatalf("dependency-free binary runtime edges = %v, want none", got)
	}
	for _, forbiddenRef := range []string{
		"pkg:npm/@research-engineering/agentic-proofkit@1.2.3",
		"pkg:pypi/agentic-proofkit@1.2.3",
		toolRef,
	} {
		for ref, edges := range dependencyByRef {
			if slices.Contains(edges, forbiddenRef) {
				t.Fatalf("%s invented runtime edge from %s", forbiddenRef, ref)
			}
		}
	}
}

func TestBinaryRuntimeModulesRejectsUnreadableBuildInfo(t *testing.T) {
	for _, item := range []struct {
		name   string
		reader io.ReaderAt
	}{
		{name: "empty", reader: bytes.NewReader(nil)},
		{name: "non-Go", reader: strings.NewReader("opaque artifact content")},
		{name: "reader failure", reader: failingBuildInfoReader{}},
	} {
		t.Run(item.name, func(t *testing.T) {
			modules, err := binaryRuntimeModules(item.reader)
			assertUnreadableBuildInfo(t, err)
			if modules != nil {
				t.Fatalf("binaryRuntimeModules() modules=%v, want no admitted inventory", modules)
			}
		})
	}
}

func TestAdmitReleaseFileRejectsUnreadableRequiredBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agentic-proofkit")
	writeFile(t, path, "opaque artifact content")
	component, modules, isBinary, err := admitReleaseFile(packageJSON{}, path, map[string]struct{}{path: {}}, nil)
	assertUnreadableBuildInfo(t, err)
	if !reflect.DeepEqual(component, cyclonedxComponent{}) || modules != nil || isBinary {
		t.Fatalf("admitReleaseFile() returned partial evidence: %#v, %v, %v", component, modules, isBinary)
	}
}

func TestReleaseFileEvidenceAllowsNonbinaryWithoutBuildInfo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.tgz")
	content := []byte("opaque artifact content")
	writeFile(t, path, string(content))
	components, inventories, err := releaseFileEvidence(packageJSON{}, []string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 || len(inventories) != 0 {
		t.Fatalf("releaseFileEvidence() components=%v, inventories=%v, want one nonbinary subject", components, inventories)
	}
	assertReleaseSubjectDigest(t, components[0], path, content)
}

func TestDependencyFreeGoBinaryBuildInfo(t *testing.T) {
	for _, stripped := range []bool{false, true} {
		name := "nonstripped"
		if stripped {
			name = "stripped"
		}
		t.Run(name, func(t *testing.T) {
			path := buildDependencyFreeGoBinary(t, stripped)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			modules, err := binaryRuntimeModules(bytes.NewReader(content))
			if err != nil || len(modules) != 0 {
				t.Fatalf("binaryRuntimeModules() modules=%v, error=%v, want valid empty inventory", modules, err)
			}
			binaryPaths := map[string]struct{}{path: {}}
			component, modules, isBinary, err := admitReleaseFile(packageJSON{}, path, binaryPaths, nil)
			if err != nil || !isBinary || len(modules) != 0 {
				t.Fatalf("admitReleaseFile() modules=%v, isBinary=%v, error=%v, want valid empty inventory", modules, isBinary, err)
			}
			assertReleaseSubjectDigest(t, component, path, content)

			t.Run("truncated", func(t *testing.T) {
				truncated := content[:16]
				_, err := binaryRuntimeModules(bytes.NewReader(truncated))
				assertUnreadableBuildInfo(t, err)
				truncatedPath := filepath.Join(t.TempDir(), "agentic-proofkit")
				writeFile(t, truncatedPath, string(truncated))
				_, _, _, err = admitReleaseFile(packageJSON{}, truncatedPath, map[string]struct{}{truncatedPath: {}}, nil)
				assertUnreadableBuildInfo(t, err)
			})

			for _, mutation := range []string{"identity swap", "in-place mutation"} {
				t.Run(mutation, func(t *testing.T) {
					selectedPath := filepath.Join(t.TempDir(), "agentic-proofkit")
					writeFile(t, selectedPath, string(content))
					_, _, _, err := admitReleaseFile(packageJSON{}, selectedPath, map[string]struct{}{selectedPath: {}}, func(selected string) error {
						if mutation == "identity swap" {
							replacement := filepath.Join(t.TempDir(), "replacement")
							writeFile(t, replacement, string(content))
							return os.Rename(replacement, selected)
						}
						changed := bytes.Clone(content)
						changed[len(changed)-1] ^= 1
						return os.WriteFile(selected, changed, 0o600)
					})
					if err == nil || !strings.Contains(err.Error(), "changed during admission") {
						t.Fatalf("admitReleaseFile() error=%v, want %s rejection", err, mutation)
					}
				})
			}
		})
	}
}

type failingBuildInfoReader struct{}

func (failingBuildInfoReader) ReadAt([]byte, int64) (int, error) {
	return 0, errors.New("private reader failure details")
}

func assertUnreadableBuildInfo(t *testing.T, err error) {
	t.Helper()
	if err == nil || err.Error() != "required release binary Go build info is unreadable" || errors.Unwrap(err) != nil {
		t.Fatalf("error=%v, want sanitized unreadable build info error without a wrapped cause", err)
	}
}

func assertReleaseSubjectDigest(t *testing.T, component cyclonedxComponent, path string, content []byte) {
	t.Helper()
	digest := sha256.Sum256(content)
	wantHashes := []cyclonedxHash{{Alg: "SHA-256", Content: hex.EncodeToString(digest[:])}}
	if component.BOMRef != "file:"+filepath.ToSlash(path) || !slices.Equal(component.Hashes, wantHashes) {
		t.Fatalf("release subject=%#v, want exact path and byte digest", component)
	}
}

func buildDependencyFreeGoBinary(t *testing.T, stripped bool) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.invalid/sbom-fixture\n\ngo 1.27\n")
	writeFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	path := filepath.Join(root, "agentic-proofkit")
	args := []string{"build", "-buildvcs=false", "-o", path}
	if stripped {
		args = append(args, "-ldflags=-s -w")
	}
	args = append(args, ".")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir = root
	command.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=", "GOPROXY=off", "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build dependency-free Go binary: %v\n%s", err, output)
	}
	return path
}

func TestReleaseFileEvidenceRejectsDeterministicIdentitySwap(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "agentic-proofkit")
	replacement := filepath.Join(root, "replacement")
	displaced := filepath.Join(root, "displaced")
	writeFile(t, path, "first-binary")
	writeFile(t, replacement, "other-binary")
	manifest := packageJSON{Name: "@research-engineering/agentic-proofkit", Version: "1.2.3", License: "MIT"}

	_, _, err := releaseFileEvidence(manifest, []string{path}, func(selected string) error {
		if selected != path {
			t.Fatalf("afterHash selected %s, want %s", selected, path)
		}
		if err := os.Rename(path, displaced); err != nil {
			return err
		}
		return os.Rename(replacement, path)
	})
	if err == nil || !strings.Contains(err.Error(), "changed during admission") {
		t.Fatalf("releaseFileEvidence() error=%v, want identity-swap rejection", err)
	}
}

func TestReleaseFileEvidenceRejectsDeterministicInPlaceMutation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "agentic-proofkit")
	writeFile(t, path, "first-binary")
	manifest := packageJSON{Name: "@research-engineering/agentic-proofkit", Version: "1.2.3", License: "MIT"}

	_, _, err := releaseFileEvidence(manifest, []string{path}, func(selected string) error {
		return os.WriteFile(selected, []byte("other-binary"), 0o600)
	})
	if err == nil || !strings.Contains(err.Error(), "changed during admission") {
		t.Fatalf("releaseFileEvidence() error=%v, want in-place mutation rejection", err)
	}
}

func TestReadPackageJSONRejectsAmbiguousJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.json")
	if err := os.WriteFile(path, []byte(`{"name":"agentic-proofkit","name":"other","version":"1.2.3","license":"MIT"}`), 0o600); err != nil {
		t.Fatalf("write package manifest: %v", err)
	}

	_, err := readPackageJSON(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("readPackageJSON() error = %v, want duplicate-key rejection", err)
	}
}

func TestReleaseFilePathsRequireReleasePlatformBinarySet(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T)
		want  string
	}{
		{
			name: "missing owner binary",
			setup: func(t *testing.T) {
				writeReleasePlatformBinaries(t, releaseplatform.BinaryPaths()[:len(releaseplatform.BinaryPaths())-1])
			},
			want: "missing release platform binary",
		},
		{
			name: "unmanaged stale binary",
			setup: func(t *testing.T) {
				writeReleasePlatformBinaries(t, releaseplatform.BinaryPaths())
				writeFile(t, filepath.Join("dist", "platform", "freebsd-x64", releaseplatform.BinaryName), "stale")
			},
			want: "unmanaged release platform binary",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			withTempWD(t, func() {
				item.setup(t)

				_, err := releaseFilePaths()
				if err == nil || !strings.Contains(err.Error(), item.want) {
					t.Fatalf("releaseFilePaths() error=%v, want %q", err, item.want)
				}
			})
		})
	}
	t.Run("complete owner set", func(t *testing.T) {
		withTempWD(t, func() {
			writeReleasePlatformBinaries(t, releaseplatform.BinaryPaths())
			paths, err := releaseFilePaths()
			if err != nil {
				t.Fatalf("releaseFilePaths() error=%v", err)
			}
			if len(paths) != len(releaseplatform.BinaryPaths()) {
				t.Fatalf("releaseFilePaths() paths=%v, want owner binary set only", paths)
			}
		})
	})
}

func TestSBOMSerialNumberIsDeterministicCycloneDXURN(t *testing.T) {
	manifest := packageJSON{Name: "@research-engineering/agentic-proofkit", Version: "1.2.3"}
	got := sbomSerialNumber(manifest)
	if !strings.HasPrefix(got, "urn:uuid:") {
		t.Fatalf("sbomSerialNumber()=%q, want urn:uuid prefix", got)
	}
	uuid := strings.TrimPrefix(got, "urn:uuid:")
	if len(uuid) != len("00000000-0000-0000-0000-000000000000") {
		t.Fatalf("sbomSerialNumber()=%q, want RFC 4122 UUID length", got)
	}
	for _, index := range []int{8, 13, 18, 23} {
		if uuid[index] != '-' {
			t.Fatalf("sbomSerialNumber()=%q, want UUID hyphen at %d", got, index)
		}
	}
	if uuid[14] != '5' {
		t.Fatalf("sbomSerialNumber()=%q, want UUID v5 version nibble", got)
	}
	if got != sbomSerialNumber(manifest) {
		t.Fatalf("sbomSerialNumber() must be deterministic")
	}
	changed := sbomSerialNumber(packageJSON{Name: manifest.Name, Version: "1.2.4"})
	if got == changed {
		t.Fatalf("sbomSerialNumber()=%q did not change when package version changed", got)
	}
}

func hasProperty(component cyclonedxComponent, name, value string) bool {
	for _, property := range component.Properties {
		if property.Name == name && property.Value == value {
			return true
		}
	}
	return false
}

func writeReleasePlatformBinaries(t *testing.T, paths []string) {
	t.Helper()
	for _, path := range paths {
		writeFile(t, path, "binary")
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func withTempWD(t *testing.T, fn func()) {
	t.Helper()
	root := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	}()
	fn()
}
