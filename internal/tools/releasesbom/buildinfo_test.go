package main

import (
	"bytes"
	"context"
	gobuildinfo "debug/buildinfo"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

func TestBinaryBuildInfoReleaseTargetMatrix(t *testing.T) {
	for _, target := range releaseplatform.Targets() {
		for _, stripped := range []bool{false, true} {
			for _, dependency := range []bool{false, true} {
				name := target.PlatformSuffix
				if stripped {
					name += "/stripped"
				}
				if dependency {
					name += "/dependency"
				}
				t.Run(name, func(t *testing.T) {
					content := buildGoMetadataFixture(t, target.GOOS, target.GOARCH, stripped, dependency)
					modules, err := binaryRuntimeModules(bytes.NewReader(content))
					want := []goModuleRecord{}
					if dependency {
						want = append(want, goModuleRecord{Path: "./dependency", Version: "(devel)"})
					}
					if err != nil || !reflect.DeepEqual(modules, want) {
						t.Fatalf("modules=%v, err=%v, want source-defined %v", modules, err, want)
					}
				})
			}
		}
	}
}

func TestBinaryBuildInfoRejectsSilentMetadataLoss(t *testing.T) {
	content := buildGoMetadataFixture(t, runtime.GOOS, runtime.GOARCH, true, true)
	moduleStart := bytes.Index(content, []byte("\xff Go buildinf:")) + 32
	if moduleStart < 32 {
		t.Fatal("fixture has no build-info header")
	}
	versionSize, width := binary.Uvarint(content[moduleStart:])
	if width <= 0 {
		t.Fatal("fixture has no inline version")
	}
	moduleLength := moduleStart + width + int(versionSize)
	moduleSize, moduleWidth := binary.Uvarint(content[moduleLength:])
	if moduleWidth <= 0 || moduleSize < 33 || moduleSize > uint64(len(content)-moduleLength-moduleWidth) {
		t.Fatal("fixture has no bounded framed module payload")
	}
	payloadStart := moduleLength + moduleWidth
	payloadEnd := payloadStart + int(moduleSize)
	terminal := payloadEnd - 17
	depOffset := bytes.Index(content[payloadStart:payloadEnd], []byte("dep\tfixture.invalid/dependency"))
	dependency := payloadStart + depOffset + 3
	if content[terminal] != '\n' || depOffset < 0 || content[dependency] != '\t' {
		t.Fatal("fixture lacks independently located module records")
	}
	for _, item := range []struct {
		name   string
		offset int
		value  byte
	}{
		{"terminal newline", terminal, '!'},
		{"module length", moduleLength, 0},
		{"dependency record", dependency, '\n'},
	} {
		t.Run(item.name, func(t *testing.T) {
			changed := bytes.Clone(content)
			changed[item.offset] = item.value
			if _, err := gobuildinfo.Read(bytes.NewReader(changed)); err != nil {
				t.Fatalf("control must exercise silent stdlib acceptance: %v", err)
			}
			modules, err := binaryRuntimeModules(bytes.NewReader(changed))
			assertUnreadableBuildInfo(t, err)
			if modules != nil {
				t.Fatalf("partial inventory=%v", modules)
			}
			path := filepath.Join(t.TempDir(), "agentic-proofkit")
			writeFile(t, path, string(changed))
			component, modules, isBinary, err := admitReleaseFile(packageJSON{}, path, map[string]struct{}{path: {}}, nil)
			assertUnreadableBuildInfo(t, err)
			if !reflect.DeepEqual(component, cyclonedxComponent{}) || modules != nil || isBinary {
				t.Fatal("malformed metadata produced partial subject evidence")
			}
		})
	}
}

func buildGoMetadataFixture(t *testing.T, goos, goarch string, stripped, dependency bool) []byte {
	t.Helper()
	root := t.TempDir()
	module := "module fixture.invalid/application\n\ngo 1.24.0\n"
	source := "package main\nfunc main() {}\n"
	if dependency {
		module += "\nrequire fixture.invalid/dependency v1.2.3\nreplace fixture.invalid/dependency => ./dependency\n"
		if err := os.Mkdir(filepath.Join(root, "dependency"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(root, "dependency", "go.mod"), "module fixture.invalid/dependency\n\ngo 1.24.0\n")
		writeFile(t, filepath.Join(root, "dependency", "dependency.go"), "package dependency\nfunc Message() string { return \"known-dependency\" }\n")
		source = "package main\nimport (\"fmt\"; \"fixture.invalid/dependency\")\nfunc main() { fmt.Print(dependency.Message()) }\n"
	}
	writeFile(t, filepath.Join(root, "go.mod"), module)
	writeFile(t, filepath.Join(root, "main.go"), source)
	path := filepath.Join(root, "subject")
	args := []string{"build", "-trimpath", "-o", path}
	if stripped {
		args = append(args, "-ldflags=-s -w")
	}
	args = append(args, ".")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir = root
	command.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GO111MODULE=on", "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v\n%s", err, output)
	}
	if dependency && goos == runtime.GOOS && goarch == runtime.GOARCH {
		output, err := exec.CommandContext(ctx, path).CombinedOutput()
		if err != nil || string(output) != "known-dependency" {
			t.Fatalf("execute native fixture: %q, %v", output, err)
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}
