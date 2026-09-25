//go:build darwin || linux

package publicapi

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestScanRejectsFIFOWithoutWriter(t *testing.T) {
	for _, scenario := range []string{"direct", "symlink", "kind-swap", "canonical-swap", "repository-root", "repository-root-symlink", "package-root", "package-root-symlink"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestScanFIFOChild$")
			command.Env = append(os.Environ(), "PROOFKIT_SCAN_FIFO="+scenario)
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("scanner blocked without a FIFO writer: %v", ctx.Err())
			}
			if err != nil {
				t.Fatalf("FIFO rejection failed: %v\n%s", err, output)
			}
		})
	}
}

func TestScanFIFOChild(t *testing.T) {
	scenario := os.Getenv("PROOFKIT_SCAN_FIFO")
	if scenario == "" {
		return
	}
	root := t.TempDir()
	source := filepath.Join(root, "source.ts")
	makeFIFO := func() {
		t.Helper()
		if err := unix.Mkfifo(source, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	lexical := "source.ts"
	directoryScenario := strings.HasPrefix(scenario, "repository-root") || strings.HasPrefix(scenario, "package-root")
	if scenario == "direct" || scenario == "symlink" || directoryScenario {
		makeFIFO()
	} else if err := os.WriteFile(source, []byte("export const value = 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if scenario == "symlink" || scenario == "canonical-swap" || strings.HasSuffix(scenario, "-symlink") {
		lexical = "alias.ts"
		if err := os.Symlink("source.ts", filepath.Join(root, lexical)); err != nil {
			t.Fatal(err)
		}
	}
	if strings.HasPrefix(scenario, "repository-root") {
		scan := newScanCache(filepath.Join(root, lexical), 4096)
		if scan.root != nil {
			scan.root.Close()
			t.Fatal("FIFO was admitted as a repository root")
		}
		if !errors.Is(scan.initErr, unix.ENOTDIR) {
			t.Fatalf("expected repository directory rejection, got %v", scan.initErr)
		}
		return
	}
	swapped := false
	if scenario == "kind-swap" || scenario == "canonical-swap" {
		scanAdmissionBarrier = func(stage, _ string) {
			if stage != "canonical_resolved" || swapped {
				return
			}
			swapped = true
			if err := os.Rename(source, source+".old"); err != nil {
				t.Fatal(err)
			}
			makeFIFO()
			if scenario == "canonical-swap" {
				alias := filepath.Join(root, lexical)
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("source.ts.old", alias); err != nil {
					t.Fatal(err)
				}
			}
		}
		defer func() { scanAdmissionBarrier = nil }()
	}
	scan := newScanCache(root, 4096)
	if scan.initErr != nil {
		t.Fatal(scan.initErr)
	}
	defer scan.root.Close()
	if strings.HasPrefix(scenario, "package-root") {
		_, _, _, packageRoot, err := readPackageManifest(scan, filepath.Join(lexical, "package.json"))
		if packageRoot != nil {
			packageRoot.Close()
			t.Fatal("FIFO was admitted as a package root")
		}
		if !errors.Is(err, unix.ENOTDIR) || !strings.Contains(err.Error(), "open referenced package root") {
			t.Fatalf("expected package directory rejection, got %v", err)
		}
		if scan.bytesRead != 0 || len(scan.files) != 0 {
			t.Fatal("invalid package root caused reads or caching")
		}
		return
	}
	_, err := scan.readFileSnapshot(lexical, "FIFO source", 4096)
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected regular-file rejection, got %v", err)
	}
	if (scenario == "kind-swap" || scenario == "canonical-swap") && !swapped {
		t.Fatal("admission swap did not run")
	}
	if scan.bytesRead != 0 || len(scan.files) != 0 {
		t.Fatal("rejected FIFO was read or cached")
	}
}

func TestScanDirectoryRootPreservesEmptyAndTrailingSeparator(t *testing.T) {
	empty := newScanCache("", 4096)
	if empty.root != nil {
		empty.root.Close()
		t.Fatal("empty root implicitly selected a directory")
	}
	if empty.initErr == nil {
		t.Fatal("empty root was admitted")
	}
	scan := newScanCache(t.TempDir()+string(os.PathSeparator), 4096)
	if scan.initErr != nil {
		t.Fatal(scan.initErr)
	}
	if err := scan.root.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestScanDirectoryRootPreservesInitialSymlinkTraversal(t *testing.T) {
	root := writeTypeScriptPackageFixture(t)
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	aliases := t.TempDir()
	alias := filepath.Join(aliases, "selected")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(aliases, "nested")
	if err := os.Symlink(filepath.Join(root, "nested"), nested); err != nil {
		t.Fatal(err)
	}
	// Joining would clean away the native symlink/.. traversal under test.
	for _, selected := range []string{alias, nested + "/.."} {
		output, code, err := Verify(publicAPIManifest(), Options{RepoRoot: selected})
		if err != nil || code != 0 || output["entryCount"] != 1 {
			t.Fatalf("initial root selection changed: code=%d err=%v output=%#v", code, err, output)
		}
	}
	for _, selected := range []string{".", ".."} {
		t.Run(selected, func(t *testing.T) {
			working := root
			if selected == ".." {
				working = filepath.Join(root, "nested")
			}
			t.Chdir(working)
			output, code, err := Verify(publicAPIManifest(), Options{RepoRoot: selected})
			if err != nil || code != 0 || output["entryCount"] != 1 {
				t.Fatalf("relative root selection changed: code=%d err=%v", code, err)
			}
		})
	}
}
