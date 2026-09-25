package requirementbrowser

import (
	"context"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBrowserLauncherChild(t *testing.T) {
	mode := os.Getenv("PROOFKIT_BROWSER_CHILD")
	if mode == "" {
		return
	}
	if _, err := os.Stdout.Write([]byte{1}); err != nil {
		os.Exit(2)
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		os.Exit(3)
	}
	if mode == "failure" {
		os.Exit(7)
	}
	os.Exit(0)
}

func TestBrowserLauncherCompletionAndCancellation(t *testing.T) {
	for _, mode := range []string{"success", "failure", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			watchers := browserContextWatchers()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			input, release, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			defer release.Close()
			ready, output, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer ready.Close()
			defer output.Close()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBrowserLauncherChild$")
			command.Env = append(os.Environ(), "PROOFKIT_BROWSER_CHILD="+mode)
			command.Stdin, command.Stdout = input, output
			done, err := startBrowserCommand(command)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("launcher Wait owner did not finish cleanup")
				}
			}()
			if err := ready.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(ready, make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				t.Fatalf("launcher completed before child release: %v", err)
			default:
			}
			if mode == "cancel" {
				cancel()
			} else if err := release.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if (err == nil) != (mode == "success") {
					t.Fatalf("completion error=%v for %s", err, mode)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("launcher completion was not delivered")
			}
			if command.ProcessState == nil || command.ProcessState.Success() != (mode == "success") {
				t.Fatalf("child not reaped with expected status: %v", command.ProcessState)
			}
			select {
			case _, ok := <-done:
				if ok {
					t.Fatal("multiple completion results")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("completion channel was not closed")
			}
			deadline := time.Now().Add(time.Second)
			for browserContextWatchers() > watchers {
				if time.Now().After(deadline) {
					t.Fatal("CommandContext watcher survived Wait completion")
				}
				runtime.Gosched()
			}
		})
	}
}

func TestBrowserLauncherStartFailure(t *testing.T) {
	done, err := startBrowserCommand(exec.CommandContext(t.Context(), t.TempDir()+"/missing"))
	if err == nil || done != nil || !strings.Contains(err.Error(), "open browser") {
		t.Fatalf("start failure: done=%v error=%v", done, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := startBrowserProcess(ctx, os.Args[0]); err == nil {
		t.Fatal("cancelled launcher started successfully")
	}
}

func browserContextWatchers() int {
	stack := make([]byte, 1<<20)
	n := runtime.Stack(stack, true)
	return strings.Count(string(stack[:n]), "os/exec.(*Cmd).watchCtx")
}
