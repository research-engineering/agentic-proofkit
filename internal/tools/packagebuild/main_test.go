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
	wantCases := strings.Join([]string{
		`  Darwin/aarch64) platform="darwin-arm64" ;;`,
		`  Darwin/amd64) platform="darwin-x64" ;;`,
		`  Darwin/arm64) platform="darwin-arm64" ;;`,
		`  Darwin/x86_64) platform="darwin-x64" ;;`,
		`  Linux/aarch64) platform="linux-arm64" ;;`,
		`  Linux/amd64) platform="linux-x64" ;;`,
		`  Linux/arm64) platform="linux-arm64" ;;`,
		`  Linux/x86_64) platform="linux-x64" ;;`,
	}, "\n")
	gotCases, err := wrapperPlatformCases(releaseplatform.Targets())
	if err != nil {
		t.Fatalf("wrapperPlatformCases() error = %v", err)
	}
	if gotCases != wantCases {
		t.Fatalf("wrapperPlatformCases() =\n%s\nwant exact OS/architecture mapping\n%s", gotCases, wantCases)
	}
	if strings.Count(wrapper, wantCases) != 1 {
		t.Fatalf("wrapperScript() must embed the exact platform mapping once:\n%s", wrapper)
	}
	for _, required := range []string{
		"AGENTIC_PROOFKIT_LAUNCHER_PROFILE=npm_offline\n",
		"AGENTIC_PROOFKIT_PYTHON_EXECUTABLE=\n",
		"export AGENTIC_PROOFKIT_LAUNCHER_PROFILE\n",
		"export AGENTIC_PROOFKIT_PYTHON_EXECUTABLE\n",
		"exec \"$binary\" \"$@\"\n",
	} {
		if !strings.Contains(wrapper, required) {
			t.Fatalf("wrapperScript() missing launcher-profile boundary %q:\n%s", required, wrapper)
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
