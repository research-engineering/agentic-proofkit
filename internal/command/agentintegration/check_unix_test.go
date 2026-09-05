//go:build darwin || linux

package agentintegration

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/rootpath"
	"golang.org/x/sys/unix"
)

func TestCheckFIFONeverRead(t *testing.T) {
	const helperEnvironment = "PROOFKIT_INTEGRATION_CHECK_FIFO_HELPER"
	if os.Getenv(helperEnvironment) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCheckFIFONeverRead$")
		command.Env = append(os.Environ(), helperEnvironment+"=1")
		if err := command.Run(); err != nil || ctx.Err() != nil {
			t.Fatal("FIFO check failed or blocked beyond its bounded subprocess lifetime")
		}
		return
	}
	root := t.TempDir()
	document := checkTestDocument(t, "codex")
	selected := filepath.Join(root, document.path)
	checkMkdir(t, filepath.Dir(selected))
	if err := unix.Mkfifo(selected, 0o600); err != nil {
		t.Fatal("FIFO fixture creation failed")
	}
	before := checkTree(t, root)
	dependencies := nativeCheckDependencies()
	opens := 0
	dependencies.openFile = func(lease *repositorytransaction.InspectionLease, path string) (repositorytransaction.InspectionFile, rootpath.RouteObservation, error) {
		opens++
		file, route, err := lease.OpenObservedExactRegularFile(path)
		if file != nil {
			_ = file.Close()
			t.Fatal("FIFO unexpectedly returned an opened regular file")
		}
		return file, route, err
	}
	result, err := checkWithDependencies(context.Background(), root, document, dependencies)
	if err != nil || result.State() != "invalid" || opens != 2 {
		t.Fatal("FIFO was not classified invalid by both non-reading observations")
	}
	checkUnchanged(t, root, before)
}

func TestCheckReobservesCompleteRoute(t *testing.T) {
	for _, tool := range []string{"codex", "claude"} {
		for _, scenario := range []string{"missing position", "parent identity", "parent mode", "unsafe kind", "unsafe identity"} {
			t.Run(tool+"/"+scenario, func(t *testing.T) {
				root := t.TempDir()
				document := checkTestDocument(t, tool)
				selected := filepath.Join(root, document.path)
				parent := filepath.Dir(selected)
				var originalLeaf fs.FileInfo
				switch scenario {
				case "missing position":
				case "unsafe kind", "unsafe identity":
					checkMkdir(t, selected)
				default:
					checkWrite(t, selected, document.Content())
					var err error
					originalLeaf, err = os.Stat(selected)
					if err != nil {
						t.Fatal(err)
					}
				}
				dependencies := nativeCheckDependencies()
				opens := 0
				dependencies.openFile = func(lease *repositorytransaction.InspectionLease, path string) (repositorytransaction.InspectionFile, rootpath.RouteObservation, error) {
					opens++
					if opens == 2 {
						switch scenario {
						case "missing position":
							checkMkdir(t, parent)
						case "parent identity":
							before, err := os.Stat(parent)
							if err != nil {
								t.Fatal(err)
							}
							if err := os.Rename(parent, parent+".saved"); err != nil {
								t.Fatal(err)
							}
							checkMkdir(t, parent)
							if err := os.Link(filepath.Join(parent+".saved", "SKILL.md"), selected); err != nil {
								t.Fatal(err)
							}
							after, err := os.Stat(parent)
							if err != nil || os.SameFile(before, after) {
								t.Fatal("parent identity did not change")
							}
						case "parent mode":
							if err := os.Chmod(parent, 0o500); err != nil {
								t.Fatal(err)
							}
							t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
						case "unsafe kind":
							if err := os.Remove(selected); err != nil {
								t.Fatal(err)
							}
							if err := unix.Mkfifo(selected, 0o600); err != nil {
								t.Fatal(err)
							}
						case "unsafe identity":
							if err := os.Rename(selected, selected+".saved"); err != nil {
								t.Fatal(err)
							}
							checkMkdir(t, selected)
						}
						if originalLeaf != nil {
							after, err := os.Stat(selected)
							if err != nil || !sameCheckFile(originalLeaf, after) {
								t.Fatal("route fixture changed leaf observation")
							}
						}
					}
					return lease.OpenObservedExactRegularFile(path)
				}
				result, err := checkWithDependencies(context.Background(), root, document, dependencies)
				checkWantError(t, result, err, root)
				if opens != 2 {
					t.Fatal("route comparison did not reach two complete observations")
				}
			})
		}
	}
}
