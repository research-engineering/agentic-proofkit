package releaseplatform

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestTargetsOwnExactReleaseMatrix(t *testing.T) {
	expected := []Target{
		{
			BinaryPath:      "dist/platform/darwin-arm64/agentic-proofkit",
			GOARCH:          "arm64",
			GOOS:            "darwin",
			NPMCPU:          "arm64",
			NPMOS:           "darwin",
			PackageTarEntry: "package/dist/platform/darwin-arm64/agentic-proofkit",
			PlatformSuffix:  "darwin-arm64",
			PlatformTag:     "macosx_12_0_arm64",
			WheelTag:        "py3-none-macosx_12_0_arm64",
		},
		{
			BinaryPath:      "dist/platform/darwin-x64/agentic-proofkit",
			GOARCH:          "amd64",
			GOOS:            "darwin",
			NPMCPU:          "x64",
			NPMOS:           "darwin",
			PackageTarEntry: "package/dist/platform/darwin-x64/agentic-proofkit",
			PlatformSuffix:  "darwin-x64",
			PlatformTag:     "macosx_12_0_x86_64",
			WheelTag:        "py3-none-macosx_12_0_x86_64",
		},
		{
			BinaryPath:      "dist/platform/linux-arm64/agentic-proofkit",
			GOARCH:          "arm64",
			GOOS:            "linux",
			NPMCPU:          "arm64",
			NPMOS:           "linux",
			PackageTarEntry: "package/dist/platform/linux-arm64/agentic-proofkit",
			PlatformSuffix:  "linux-arm64",
			PlatformTag:     "manylinux_2_17_aarch64",
			WheelTag:        "py3-none-manylinux_2_17_aarch64",
		},
		{
			BinaryPath:      "dist/platform/linux-x64/agentic-proofkit",
			GOARCH:          "amd64",
			GOOS:            "linux",
			NPMCPU:          "x64",
			NPMOS:           "linux",
			PackageTarEntry: "package/dist/platform/linux-x64/agentic-proofkit",
			PlatformSuffix:  "linux-x64",
			PlatformTag:     "manylinux_2_17_x86_64",
			WheelTag:        "py3-none-manylinux_2_17_x86_64",
		},
	}

	if !reflect.DeepEqual(Targets(), expected) {
		t.Fatalf("Targets() = %#v, want %#v", Targets(), expected)
	}
	for _, target := range Targets() {
		if strings.Contains(target.BinaryPath, `\`) {
			t.Fatalf("BinaryPath %q must use POSIX separators", target.BinaryPath)
		}
	}
}

func TestTargetProjectionsAreImmutableAndExact(t *testing.T) {
	targets := Targets()
	targets[0].PlatformSuffix = "mutated"

	if got := PlatformSuffixes(); !reflect.DeepEqual(got, []string{"darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"}) {
		t.Fatalf("PlatformSuffixes() = %#v", got)
	}
	if got := NPMOSValues(); !reflect.DeepEqual(got, []string{"darwin", "linux"}) {
		t.Fatalf("NPMOSValues() = %#v", got)
	}
	if got := NPMCPUValues(); !reflect.DeepEqual(got, []string{"arm64", "x64"}) {
		t.Fatalf("NPMCPUValues() = %#v", got)
	}
	if got := PackageTarEntries(); !reflect.DeepEqual(got, []string{
		"package/dist/platform/darwin-arm64/agentic-proofkit",
		"package/dist/platform/darwin-x64/agentic-proofkit",
		"package/dist/platform/linux-arm64/agentic-proofkit",
		"package/dist/platform/linux-x64/agentic-proofkit",
	}) {
		t.Fatalf("PackageTarEntries() = %#v", got)
	}
	if got := BinaryPaths(); !reflect.DeepEqual(got, []string{
		"dist/platform/darwin-arm64/agentic-proofkit",
		"dist/platform/darwin-x64/agentic-proofkit",
		"dist/platform/linux-arm64/agentic-proofkit",
		"dist/platform/linux-x64/agentic-proofkit",
	}) {
		t.Fatalf("BinaryPaths() = %#v", got)
	}
	if _, ok := PlatformSuffixSet()["mutated"]; ok {
		t.Fatalf("PlatformSuffixSet() exposed mutated caller copy")
	}
}

func TestTargetByPlatformSuffix(t *testing.T) {
	target, ok := TargetByPlatformSuffix("linux-x64")
	if !ok {
		t.Fatal("TargetByPlatformSuffix() did not find linux-x64")
	}
	if target.GOOS != "linux" || target.GOARCH != "amd64" || target.NPMCPU != "x64" {
		t.Fatalf("TargetByPlatformSuffix() = %#v", target)
	}
	if _, ok := TargetByPlatformSuffix("linux-amd64"); ok {
		t.Fatal("TargetByPlatformSuffix() admitted non-canonical suffix")
	}
}

func TestCurrentTargetMatchesRuntimeWhenSupported(t *testing.T) {
	target, err := CurrentTarget()
	supported := runtime.GOOS == "darwin" || runtime.GOOS == "linux"
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		supported = false
	}
	if !supported {
		if err == nil {
			t.Fatalf("CurrentTarget() = %#v, want unsupported runtime error", target)
		}
		return
	}
	if err != nil {
		t.Fatalf("CurrentTarget() error = %v", err)
	}
	if target.GOOS != runtime.GOOS || target.GOARCH != runtime.GOARCH {
		t.Fatalf("CurrentTarget() = %#v, runtime=%s/%s", target, runtime.GOOS, runtime.GOARCH)
	}
}
