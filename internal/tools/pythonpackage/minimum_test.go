package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

func TestMinimumPythonRequiresExactNativeRuntime(t *testing.T) {
	for _, identity := range []string{"linux/aarch64", "linux/arm64"} {
		if got, err := minimumDaemonArchitecture(identity, "arm64"); err != nil || got != "arm64" {
			t.Fatalf("native daemon rejected: %s %v", got, err)
		}
	}
	for _, identity := range []string{"linux/x86_64", "linux/amd64", "darwin/arm64", "linux/unknown", ""} {
		if _, err := minimumDaemonArchitecture(identity, "arm64"); err == nil {
			t.Fatalf("foreign/unknown daemon accepted: %q", identity)
		}
	}
	base := map[string]any{"python": "3.9.0", "machine": "aarch64", "uid": 65534, "pip": "26.0.1", "implementation": "cpython"}
	for _, mutation := range []struct {
		field string
		value any
	}{{"python", "3.9.25"}, {"python", "3.14.7"}, {"machine", "x86_64"}, {"uid", 0}, {"pip", "25.2"}, {"pip", "26.1"}, {"implementation", "pypy"}} {
		content, _ := json.Marshal(base)
		if err := minimumPythonIdentity(content, "arm64", true); err != nil {
			t.Fatal(err)
		}
		var changed map[string]any
		if err := json.Unmarshal(content, &changed); err != nil {
			t.Fatal(err)
		}
		changed[mutation.field] = mutation.value
		content, _ = json.Marshal(changed)
		if err := minimumPythonIdentity(content, "arm64", true); err == nil {
			t.Fatalf("runtime substitution accepted: %s=%v", mutation.field, mutation.value)
		}
	}
}

func TestMinimumPythonWheelSetRejectsOmissionAndIdentityDrift(t *testing.T) {
	manifest := testPackageManifest("1.2.3")
	set := packageSet{ArtifactKind: artifactKind, SchemaVersion: schemaVersion, PackageName: packageName, PackageVersion: manifest.Version}
	for _, target := range releaseTargets() {
		set.Packages = append(set.Packages, wheelRecord{Name: packageName, Version: manifest.Version, Filename: wheelFilename(manifest.Version, target), PlatformSuffix: target.PlatformSuffix})
	}
	native, err := minimumTarget("arm64")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := minimumSelectWheel(manifest, set, native); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*packageSet){
		func(s *packageSet) { s.Packages = s.Packages[:len(s.Packages)-1] },
		func(s *packageSet) { s.Packages[1] = s.Packages[0] },
		func(s *packageSet) { s.PackageVersion = "9.9.9" },
		func(s *packageSet) { s.Packages[0].Filename = "../other.whl" },
		func(s *packageSet) { s.Packages[0].PlatformSuffix = "unknown" },
	} {
		changed := set
		changed.Packages = append([]wheelRecord(nil), set.Packages...)
		mutate(&changed)
		if _, err := minimumSelectWheel(manifest, changed, native); err == nil {
			t.Fatal("invalid wheel inventory accepted")
		}
	}
}

func TestMinimumPythonSnapshotBytesAndLinuxPermissions(t *testing.T) {
	native, err := minimumTarget("arm64")
	if err != nil {
		t.Fatal(err)
	}
	record := wheelRecord{Version: "1.2.3", Filename: wheelFilename("1.2.3", native), PlatformSuffix: native.PlatformSuffix, Sha256: strings.Repeat("c", 64), BinarySha256: strings.Repeat("d", 64)}
	bound := minimumSnapshot{SourceRevision: strings.Repeat("a", 40), SourceDigest: strings.Repeat("b", 64), Architecture: "arm64", Wheel: record, Files: map[string]string{}}
	for _, path := range []string{"package.json", "LICENSE", sourceCLIContractPath, "python/agentic_proofkit/__init__.py", "python/agentic_proofkit/__main__.py", "python/agentic_proofkit/cli.py", "artifacts/pypi/python-packages.json", "artifacts/pypi/" + record.Filename, native.BinaryPath, "runner", minimumPipFile} {
		bound.Files[path] = strings.Repeat("e", 64)
	}
	bound.Files["artifacts/pypi/"+record.Filename] = record.Sha256
	bound.Files[native.BinaryPath] = record.BinarySha256
	bound.Files[minimumPipFile] = minimumPipSHA256
	if err := minimumValidateSnapshot(bound); err != nil {
		t.Fatal(err)
	}
	for path, digest := range bound.Files {
		delete(bound.Files, path)
		if minimumValidateSnapshot(bound) == nil {
			t.Fatalf("missing input %s accepted", path)
		}
		bound.Files[path] = digest
	}
	for _, mutate := range []func(*minimumSnapshot){
		func(s *minimumSnapshot) { s.SourceRevision = "unverified" },
		func(s *minimumSnapshot) { s.SourceDigest = "" },
		func(s *minimumSnapshot) { s.Architecture = "amd64" },
		func(s *minimumSnapshot) { s.Wheel.Sha256 = strings.Repeat("f", 64) },
		func(s *minimumSnapshot) { s.Wheel.BinarySha256 = strings.Repeat("f", 64) },
	} {
		changed := bound
		mutate(&changed)
		if minimumValidateSnapshot(changed) == nil {
			t.Fatal("snapshot identity mutation accepted")
		}
	}
	root := t.TempDir()
	for _, path := range []string{"source", "nested/contract", "runner"} {
		if err := minimumWriteInput(root, path, []byte("exact bytes"), path == "runner"); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o644)
		if path == "runner" {
			want = 0o755
		}
		if info.Mode().Perm() != want {
			t.Fatalf("input %s permissions=%o, want Linux-readable %o", path, info.Mode().Perm(), want)
		}
	}
	for _, path := range []string{root, filepath.Join(root, "nested")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o755 {
			t.Fatalf("input directory must be searchable by UID65534: %v %v", info, err)
		}
	}
	snapshot := minimumSnapshot{Files: map[string]string{"nested/contract": minimumHash([]byte("exact bytes"))}}
	if err := minimumCheckSnapshot(root, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested/contract"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := minimumCheckSnapshot(root, snapshot); err == nil {
		t.Fatal("snapshot byte replacement accepted")
	}
	if err := os.Remove(filepath.Join(root, "nested/contract")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "source"), filepath.Join(root, "nested/contract")); err != nil {
		t.Fatal(err)
	}
	if err := minimumCheckSnapshot(root, snapshot); err == nil {
		t.Fatal("snapshot symlink accepted")
	}
	if err := minimumCheckDigest([]byte("untrusted installer"), minimumPipSHA256); err == nil {
		t.Fatal("wrong installer checksum accepted")
	}
	if err := minimumWriteInput(root, "../escape", nil, false); err == nil {
		t.Fatal("escaping snapshot path accepted")
	}
}

func TestMinimumPythonDockerConfinement(t *testing.T) {
	image, err := minimumImage("arm64")
	if err != nil {
		t.Fatal(err)
	}
	got := minimumDockerArgs("/public-input", "owned-name", "arm64", image)
	want := []string{"run", "--rm", "--name", "owned-name", "--pull", "never", "--platform", "linux/arm64", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65534:65534", "--cpus", "1", "--memory", "256m", "--pids-limit", "64", "--tmpfs", "/tmp:rw,exec,nosuid,size=256m,mode=1777", "--workdir", "/input", "--mount", "type=bind,src=/public-input,dst=/input,readonly", image, "/input/runner", "verify-minimum-installed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Docker confinement changed: %v", got)
	}
	if _, err := minimumImage("386"); err == nil {
		t.Fatal("unsupported platform admitted")
	}
}

func TestMinimumPythonDockerLifecycleFailsClosed(t *testing.T) {
	input := t.TempDir()
	snapshot := []byte(`{"bound":"snapshot"}`)
	if err := os.WriteFile(filepath.Join(input, "snapshot.json"), snapshot, 0o644); err != nil {
		t.Fatal(err)
	}
	image, _ := minimumImage("arm64")
	for _, failure := range []string{"", "pull", "image architecture", "run", "cancel", "result", "cleanup query", "cleanup removal", "cleanup residue"} {
		t.Run(failure, func(t *testing.T) {
			parent, cancel := context.WithCancel(t.Context())
			defer cancel()
			inspect, query := 0, 0
			var calls []string
			command := func(ctx context.Context, args ...string) ([]byte, error) {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				joined := strings.Join(args, " ")
				calls = append(calls, joined)
				switch {
				case strings.HasPrefix(joined, "image inspect "):
					inspect++
					if inspect == 1 {
						return nil, errors.New("initial inspect unavailable")
					}
					if failure == "image architecture" {
						return []byte("linux/amd64\n"), nil
					}
					return []byte("linux/arm64\n"), nil
				case args[0] == "pull":
					if failure == "pull" {
						return nil, errors.New("pull failed")
					}
				case args[0] == "run":
					if failure == "cancel" {
						cancel()
						return nil, ctx.Err()
					}
					if failure == "run" {
						return nil, context.DeadlineExceeded
					}
					if failure == "result" {
						return []byte("{}\n"), nil
					}
					return minimumInstalledResult(minimumHash(snapshot), "arm64"), nil
				case args[0] == "ps":
					query++
					if failure == "cleanup query" {
						return nil, errors.New("query failed")
					}
					if query == 1 || failure == "cleanup residue" {
						return []byte("owned-container\n"), nil
					}
				case args[0] == "rm":
					if failure == "cleanup removal" {
						return nil, errors.New("remove failed")
					}
				case strings.HasPrefix(joined, "image rm "):
					t.Fatal("lifecycle attempted to delete shared image cache")
				}
				return nil, nil
			}
			err := minimumDockerLifecycle(parent, command, input, "owned", "arm64", image)
			if (err == nil) != (failure == "") {
				t.Fatalf("failure=%q error=%v", failure, err)
			}
			if query == 0 {
				t.Fatalf("cleanup not attempted after failure: %v", calls)
			}
		})
	}
	assertMinimumSharedImageRetention(t, input, snapshot, image)
}

func assertMinimumSharedImageRetention(t *testing.T, input string, snapshot []byte, image string) {
	t.Helper()
	for _, initial := range []string{"cached", "transient-inspect", "concurrent-pull"} {
		for _, cleanupFails := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cleanup-fails-%t", initial, cleanupFails), func(t *testing.T) {
				imagePresent := initial != "concurrent-pull"
				inspections, pulls, removals := 0, 0, 0
				containerPresent := true
				command := func(ctx context.Context, args ...string) ([]byte, error) {
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
					switch {
					case len(args) > 1 && args[0] == "image" && args[1] == "inspect":
						inspections++
						if inspections == 1 && initial != "cached" {
							return nil, errors.New("transient daemon or inspection failure")
						}
						return []byte("linux/arm64\n"), nil
					case args[0] == "pull":
						pulls++
						// Another caller can populate the same immutable digest.
						imagePresent = true
					case args[0] == "run":
						return minimumInstalledResult(minimumHash(snapshot), "arm64"), nil
					case args[0] == "ps":
						if containerPresent {
							return []byte("owned-container\n"), nil
						}
					case args[0] == "rm":
						if !reflect.DeepEqual(args, []string{"rm", "-f", "owned"}) {
							t.Fatalf("cleanup targeted an unrelated container: %v", args)
						}
						removals++
						if cleanupFails {
							return nil, errors.New("container removal failed")
						}
						containerPresent = false
					default:
						imagePresent = false
						t.Fatalf("unexpected daemon mutation or cache removal: %v", args)
					}
					return nil, nil
				}
				err := minimumDockerLifecycle(t.Context(), command, input, "owned", "arm64", image)
				if (err != nil) != cleanupFails || !imagePresent || removals != 1 {
					t.Fatalf("shared image=%t container removals=%d cleanup failure=%t error=%v", imagePresent, removals, cleanupFails, err)
				}
				wantPulls := 1
				if initial == "cached" {
					wantPulls = 0
				}
				if pulls != wantPulls {
					t.Fatalf("pulls=%d, want %d", pulls, wantPulls)
				}
			})
		}
	}
}

func TestMinimumPythonInstalledCarrierClosure(t *testing.T) {
	assertPythonFunctionCalls(t, "minimum_installed.go", "verifyMinimumInstalledPython", "installedPythonWorkflowCarriers")
	assertPythonFunctionCalls(t, "minimum_installed.go", "verifyMinimumInstalledPython", "verifyInstalledPythonCarrier")
	assertPythonFunctionCalls(t, "minimum_installed.go", "verifyMinimumInstalledPython", "workflowsmoke.VerifyCarrier")
	assertPythonFunctionCalls(t, "main.go", "run", "verifyMinimumPython")
	for _, missing := range []string{"python", "console"} {
		t.Run(missing, func(t *testing.T) {
			carriers := installedPythonWorkflowCarriers(t.TempDir(), []string{"PATH="}, "/missing/python", "/missing/console")
			index := 0
			if missing == "console" {
				index = 1
			}
			err := workflowsmoke.VerifyCarrier(t.Context(), func(ctx context.Context, invocation workflowsmoke.Invocation) (workflowsmoke.Result, error) {
				return workflowsmoke.RunProcess(ctx, carriers[index].carrier, invocation)
			})
			if err == nil {
				t.Fatal("missing installed entrypoint was accepted")
			}
		})
	}
	if bytes.Equal(minimumInstalledResult("old-snapshot", "arm64"), minimumInstalledResult("new-snapshot", "arm64")) {
		t.Fatal("installed result omitted snapshot identity")
	}
}
