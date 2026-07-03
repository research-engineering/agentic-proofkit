package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

type packageJSON struct {
	Repository repositoryJSON `json:"repository"`
	Version    string         `json:"version"`
}

type repositoryJSON struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	selectedTargets := releaseplatform.Targets()
	switch len(args) {
	case 0:
	case 1:
		switch args[0] {
		case "all":
		case "current":
			current, err := releaseplatform.CurrentTarget()
			if err != nil {
				return err
			}
			selectedTargets = []releaseplatform.Target{current}
		default:
			return fmt.Errorf("unknown package build mode %q", args[0])
		}
	default:
		return fmt.Errorf("usage: go run ./internal/tools/packagebuild [all|current]")
	}
	if err := os.RemoveAll("dist"); err != nil {
		return err
	}
	if err := os.RemoveAll("artifacts/platform"); err != nil {
		return err
	}
	if err := os.MkdirAll("dist", 0o755); err != nil {
		return err
	}
	_, _, err := packageMetadata()
	if err != nil {
		return err
	}
	for _, target := range selectedTargets {
		platformRoot := filepath.Dir(target.BinaryPath)
		if err := os.MkdirAll(platformRoot, 0o755); err != nil {
			return err
		}
		command := exec.Command(
			"go",
			"build",
			"-trimpath",
			"-buildvcs=false",
			"-ldflags=-buildid=",
			"-o",
			target.BinaryPath,
			"./cmd/agentic-proofkit",
		)
		command.Env = append(os.Environ(),
			"CGO_ENABLED=0",
			"GOOS="+target.GOOS,
			"GOARCH="+target.GOARCH,
		)
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			return fmt.Errorf("build %s/%s: %w", target.GOOS, target.GOARCH, err)
		}
	}
	wrapper, err := wrapperScript()
	if err != nil {
		return err
	}
	return os.WriteFile("dist/agentic-proofkit", []byte(wrapper), 0o755)
}

func packageMetadata() (string, string, error) {
	file, err := os.Open("package.json")
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	manifest, err := admission.DecodeTypedJSON[packageJSON](file, 16<<20)
	if err != nil {
		return "", "", err
	}
	if manifest.Version == "" {
		return "", "", fmt.Errorf("root package version is required")
	}
	if manifest.Repository.URL == "" {
		return "", "", fmt.Errorf("root package repository url is required")
	}
	return manifest.Version, manifest.Repository.URL, nil
}

func wrapperScript() (string, error) {
	platformCases, err := wrapperPlatformCases(releaseplatform.Targets())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`#!/usr/bin/env sh
set -eu

script="$0"
while [ -L "$script" ]; do
  link=$(readlink "$script")
  case "$link" in
    /*) script="$link" ;;
    *) script=$(CDPATH= cd -- "$(dirname -- "$script")" && pwd)/"$link" ;;
  esac
done

dir=$(CDPATH= cd -- "$(dirname -- "$script")" && pwd)
package_dir=$(CDPATH= cd -- "$dir/.." && pwd)

case "$(uname -s)/$(uname -m)" in
%s
  *) echo "agentic-proofkit: unsupported platform: $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

binary="$package_dir/dist/platform/$platform/agentic-proofkit"

if [ ! -x "$binary" ]; then
  echo "agentic-proofkit: missing embedded platform binary for $platform" >&2
  echo "agentic-proofkit: reinstall agentic-proofkit from the published package artifact" >&2
  exit 1
fi

exec "$binary" "$@"
`, platformCases), nil
}

func wrapperPlatformCases(targets []releaseplatform.Target) (string, error) {
	entries := []string{}
	seen := map[string]struct{}{}
	for _, target := range targets {
		for _, osName := range wrapperOSAliases(target.GOOS) {
			for _, arch := range wrapperArchAliases(target.GOARCH) {
				pattern := osName + "/" + arch
				if _, ok := seen[pattern]; ok {
					return "", fmt.Errorf("duplicate wrapper platform pattern %s", pattern)
				}
				seen[pattern] = struct{}{}
				entries = append(entries, "  "+pattern+`) platform="`+target.PlatformSuffix+`" ;;`)
			}
		}
	}
	sort.Strings(entries)
	return strings.Join(entries, "\n"), nil
}

func wrapperOSAliases(goos string) []string {
	switch goos {
	case "darwin":
		return []string{"Darwin"}
	case "linux":
		return []string{"Linux"}
	default:
		return []string{goos}
	}
}

func wrapperArchAliases(goarch string) []string {
	switch goarch {
	case "amd64":
		return []string{"amd64", "x86_64"}
	case "arm64":
		return []string{"aarch64", "arm64"}
	default:
		return []string{goarch}
	}
}
