package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

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
		t.Fatalf("stripped binary runtime edges = %v, want none", got)
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
