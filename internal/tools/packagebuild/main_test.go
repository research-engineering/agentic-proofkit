package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

func TestPackageMetadataRejectsAmbiguousPackageJSON(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"version":"1.2.3","version":"1.2.4","repository":{"url":"https://example.test/repo"}}`), 0o600); err != nil {
		t.Fatalf("write package manifest: %v", err)
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

	_, _, err = packageMetadata()
	if err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("packageMetadata() error = %v, want duplicate-key rejection", err)
	}
}

func TestWrapperScriptRoutesEveryReleasePlatformTarget(t *testing.T) {
	wrapper, err := wrapperScript()
	if err != nil {
		t.Fatalf("wrapperScript() error = %v", err)
	}
	for _, target := range releaseplatform.Targets() {
		if !strings.Contains(wrapper, `platform="`+target.PlatformSuffix+`"`) {
			t.Fatalf("wrapperScript() missing platform route for %s:\n%s", target.PlatformSuffix, wrapper)
		}
		for _, osName := range wrapperOSAliases(target.GOOS) {
			for _, arch := range wrapperArchAliases(target.GOARCH) {
				pattern := osName + "/" + arch
				if !strings.Contains(wrapper, pattern+")") {
					t.Fatalf("wrapperScript() missing uname pattern %s for %s:\n%s", pattern, target.PlatformSuffix, wrapper)
				}
			}
		}
	}
}

func TestWrapperPlatformCasesRejectDuplicatePatterns(t *testing.T) {
	targets := releaseplatform.Targets()
	targets = append(targets, targets[0])

	_, err := wrapperPlatformCases(targets)
	if err == nil || !strings.Contains(err.Error(), "duplicate wrapper platform pattern") {
		t.Fatalf("wrapperPlatformCases() error=%v, want duplicate-pattern rejection", err)
	}
}
