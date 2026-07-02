package releaseplatform

import (
	"fmt"
	"path"
	"runtime"
)

const BinaryName = "agentic-proofkit"

type Target struct {
	BinaryPath      string
	GOARCH          string
	GOOS            string
	NPMCPU          string
	NPMOS           string
	PackageTarEntry string
	PlatformSuffix  string
	PlatformTag     string
	WheelTag        string
}

var targets = []Target{
	target("darwin", "arm64", "arm64", "darwin-arm64", "macosx_11_0_arm64"),
	target("darwin", "amd64", "x64", "darwin-x64", "macosx_10_12_x86_64"),
	target("linux", "arm64", "arm64", "linux-arm64", "manylinux_2_17_aarch64"),
	target("linux", "amd64", "x64", "linux-x64", "manylinux_2_17_x86_64"),
}

func target(goos string, goarch string, npmCPU string, suffix string, platformTag string) Target {
	binaryPath := path.Join("dist", "platform", suffix, BinaryName)
	return Target{
		BinaryPath:      binaryPath,
		GOARCH:          goarch,
		GOOS:            goos,
		NPMCPU:          npmCPU,
		NPMOS:           goos,
		PackageTarEntry: path.Join("package", "dist", "platform", suffix, BinaryName),
		PlatformSuffix:  suffix,
		PlatformTag:     platformTag,
		WheelTag:        "py3-none-" + platformTag,
	}
}

func Targets() []Target {
	out := make([]Target, len(targets))
	copy(out, targets)
	return out
}

func CurrentTarget() (Target, error) {
	for _, item := range targets {
		if item.GOOS == runtime.GOOS && item.GOARCH == runtime.GOARCH {
			return item, nil
		}
	}
	return Target{}, fmt.Errorf("unsupported current platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

func TargetByPlatformSuffix(suffix string) (Target, bool) {
	for _, item := range targets {
		if item.PlatformSuffix == suffix {
			return item, true
		}
	}
	return Target{}, false
}

func NPMOSValues() []string {
	return orderedUnique(func(item Target) string {
		return item.NPMOS
	})
}

func NPMCPUValues() []string {
	return orderedUnique(func(item Target) string {
		return item.NPMCPU
	})
}

func PlatformSuffixes() []string {
	out := make([]string, 0, len(targets))
	for _, item := range targets {
		out = append(out, item.PlatformSuffix)
	}
	return out
}

func BinaryPaths() []string {
	out := make([]string, 0, len(targets))
	for _, item := range targets {
		out = append(out, item.BinaryPath)
	}
	return out
}

func PackageTarEntries() []string {
	out := make([]string, 0, len(targets))
	for _, item := range targets {
		out = append(out, item.PackageTarEntry)
	}
	return out
}

func PackageTarEntrySet() map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range targets {
		out[item.PackageTarEntry] = struct{}{}
	}
	return out
}

func PlatformSuffixSet() map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range targets {
		out[item.PlatformSuffix] = struct{}{}
	}
	return out
}

func orderedUnique(project func(Target) string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range targets {
		value := project(item)
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
