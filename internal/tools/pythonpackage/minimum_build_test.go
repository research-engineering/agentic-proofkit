package main

import (
	"bytes"
	"debug/buildinfo"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

func TestMinimumRebuildUsesReleaseCPU(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "cmd/agentic-proofkit"), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		"go.mod":                       "module example.invalid/minimum-cpu\n\ngo 1.27\n",
		"cmd/agentic-proofkit/main.go": "package main\nfunc main() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ arch, key, elevated, baseline string }{
		{"amd64", "GOAMD64", "v3", "v1"},
		{"arm64", "GOARM64", "v8.1", "v8.0"},
	} {
		t.Run(tc.arch, func(t *testing.T) {
			native, err := minimumTarget(tc.arch)
			if err != nil {
				t.Fatal(err)
			}
			parent := append(os.Environ(), tc.key+"="+tc.elevated, "PROOFKIT_CPU_CONTROL=preserved")
			original := slices.Clone(parent)
			minimumEnv, err := minimumBuildEnvironment(native, parent)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(parent, original) || !slices.Contains(minimumEnv, "PROOFKIT_CPU_CONTROL=preserved") {
				t.Fatal("build environment mutated the caller or dropped an unrelated variable")
			}
			build := func(name string, env []string, wantCPU string) []byte {
				t.Helper()
				destination := filepath.Join(root, name)
				args, err := releaseplatform.BinaryBuildArgs("1.2.3", destination)
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.CommandContext(t.Context(), "go", append([]string{"build", "-p=1"}, args...)...)
				cmd.Dir, cmd.Env = root, env
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("build %s: %v\n%s", name, err, output)
				}
				info, err := buildinfo.ReadFile(destination)
				if err != nil {
					t.Fatal(err)
				}
				settings := map[string]string{}
				for _, setting := range info.Settings {
					settings[setting.Key] = setting.Value
				}
				if settings["GOOS"] != "linux" || settings["GOARCH"] != tc.arch || settings[tc.key] != wantCPU {
					t.Fatalf("build %s: GOOS=%s GOARCH=%s %s=%s, want linux/%s %s", name, settings["GOOS"], settings["GOARCH"], tc.key, settings[tc.key], tc.arch, wantCPU)
				}
				content, err := os.ReadFile(destination)
				if err != nil {
					t.Fatal(err)
				}
				return content
			}
			direct := append(slices.Clone(parent), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+tc.arch)
			expected := build("baseline", append(slices.Clone(direct), tc.key+"="+tc.baseline), tc.baseline)
			rebuilt := build("minimum", minimumEnv, tc.baseline)
			if !bytes.Equal(rebuilt, expected) {
				t.Fatal("the minimum-runtime rebuild differs from the independently built release baseline")
			}
			elevated := build("elevated", direct, tc.elevated)
			if minimumCheckDigest(elevated, minimumHash(expected)) == nil {
				t.Fatal("a different CPU build was admitted as the baseline wheel binary")
			}
		})
	}
}
