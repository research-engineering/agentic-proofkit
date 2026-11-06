package main

import (
	"debug/buildinfo"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

func TestPackageBuildPinsAndVerifiesArchitectureBaseline(t *testing.T) {
	target, err := releaseplatform.CurrentTarget()
	if err != nil {
		t.Fatal(err)
	}
	var key, elevated, baseline string
	switch runtime.GOARCH {
	case "amd64":
		key, elevated, baseline = "GOAMD64", "v3", "v1"
	case "arm64":
		key, elevated, baseline = "GOARM64", "v8.1", "v8.0"
	default:
		t.Fatal("test requires an independent expected baseline for the current target")
	}
	t.Setenv(key, elevated)
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("cmd/agentic-proofkit", 0o755); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{
		"go.mod":                       "module example.invalid/package-build\n\ngo 1.27\n",
		"cmd/agentic-proofkit/main.go": "package main\nfunc main() {}\n",
		"package.json":                 `{"version":"1.2.3","repository":{"url":"https://example.test/repo"}}`,
	} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := run([]string{"current"}); err != nil {
		t.Fatal(err)
	}
	info, err := buildinfo.ReadFile(target.BinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	got := ""
	for _, setting := range info.Settings {
		if setting.Key == key {
			got = setting.Value
		}
	}
	if got != baseline || os.Getenv(key) != elevated {
		t.Fatalf("built %s=%q, want %q with inherited value unchanged", key, got, baseline)
	}
	if err := verifyBuildTarget(target, key, elevated); err == nil {
		t.Fatal("valid binary admitted under a different CPU baseline")
	}

	fixtures := t.TempDir()
	invalid := filepath.Join(fixtures, "invalid")
	if err := os.WriteFile(invalid, []byte("not a Go executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreignOS := "linux"
	if runtime.GOOS == "linux" {
		foreignOS = "darwin"
	}
	foreign := filepath.Join(fixtures, "foreign")
	build := exec.Command("go", "build", "-o", foreign, "./cmd/agentic-proofkit")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+foreignOS, "GOARCH="+runtime.GOARCH, key+"="+baseline)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build same-architecture %s control: %v\n%s", foreignOS, err, out)
	}
	stub := `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    exec cp "$PROOFKIT_TEST_BUILD_OUTPUT" "$2"
  fi
  shift
done
exit 1
`
	if err := os.WriteFile(filepath.Join(fixtures, "go"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fixtures+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, tc := range []struct{ name, output, want string }{
		{"unverified output", invalid, "read build settings"},
		{"wrong OS", foreign, "does not match release target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PROOFKIT_TEST_BUILD_OUTPUT", tc.output)
			if err := run([]string{"current"}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("successful compiler with %s: %v, want %q", tc.name, err, tc.want)
			}
			if _, err := os.Stat("dist/agentic-proofkit"); !os.IsNotExist(err) {
				t.Fatalf("launcher must not be written for %s: %v", tc.name, err)
			}
		})
	}
}

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
