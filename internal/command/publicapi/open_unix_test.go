//go:build darwin || linux

package publicapi

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestScanRejectsFIFOWithoutWriter(t *testing.T) {
	for _, scenario := range []string{"direct", "symlink", "kind-swap", "canonical-swap"} {
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
	if scenario == "direct" || scenario == "symlink" {
		makeFIFO()
	} else if err := os.WriteFile(source, []byte("export const value = 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if scenario == "symlink" || scenario == "canonical-swap" {
		lexical = "alias.ts"
		if err := os.Symlink("source.ts", filepath.Join(root, lexical)); err != nil {
			t.Fatal(err)
		}
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
