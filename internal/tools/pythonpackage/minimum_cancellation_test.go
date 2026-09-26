//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/gitfixture"
	"github.com/research-engineering/agentic-proofkit/internal/tools/repositorysnapshot"
)

func TestMinimumSourceSnapshotCancellation(t *testing.T) {
	for _, phase := range []string{"owner control", "initial", "final"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			quoted := "'" + strings.ReplaceAll(executable, "'", "'\"'\"'") + "'"
			script := "#!/bin/sh\nexec " + quoted + " -test.run=^TestMinimumSnapshotGitHelper$ -- \"$@\"\n"
			if err := os.WriteFile(filepath.Join(root, "git"), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("PROOFKIT_TEST_MINIMUM_GIT_HELPER", root)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				switch phase {
				case "owner control":
					_, err = repositorysnapshot.CaptureContext(ctx, root)
				case "initial":
					_, err = runMinimumPython(ctx)
				case "final":
					err = minimumCheckSource(ctx, root, minimumSnapshot{})
				}
				done <- err
			}()
			joined := false
			defer func() {
				cancel()
				if !joined {
					if err := os.WriteFile(filepath.Join(root, "release"), nil, 0o600); err != nil {
						t.Error(err)
					}
					<-done
				}
			}()
			readyDeadline := time.Now().Add(3 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(root, "ready")); err == nil {
					break
				}
				if time.Now().After(readyDeadline) {
					t.Fatal("Git helper did not reach the execution readiness barrier")
				}
				time.Sleep(5 * time.Millisecond)
			}
			cancel()
			select {
			case err := <-done:
				joined = true
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("source cancellation identity lost: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("source observation did not stop after cancellation of its ready Git process")
			}
		})
	}
}

func TestMinimumSnapshotGitHelper(t *testing.T) {
	root := os.Getenv("PROOFKIT_TEST_MINIMUM_GIT_HELPER")
	if root == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(root, "ready"), nil, 0o600); err != nil {
		os.Exit(2)
	}
	watchdog := time.NewTimer(5 * time.Second)
	defer watchdog.Stop()
	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
	for {
		if _, err := os.Stat(filepath.Join(root, "release")); err == nil {
			os.Exit(1)
		}
		select {
		case <-watchdog.C:
			os.Exit(3)
		case <-poll.C:
		}
	}
}

func TestMinimumFinalSourceIdentity(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "test@example.invalid"}, {"config", "user.name", "Test"}, {"add", "source.txt"}, {"commit", "-m", "initial"}} {
		if output, err := gitfixture.Command(root, args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture git command failed: %v\n%s", err, output)
		}
	}
	source, err := repositorysnapshot.CaptureContext(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	expected := minimumSnapshot{SourceRevision: source.Revision, SourceDigest: source.Digest}
	if err := minimumCheckSource(t.Context(), root, expected); err != nil {
		t.Fatalf("unchanged source rejected: %v", err)
	}
	for _, field := range []string{"revision", "digest"} {
		changed := expected
		if field == "revision" {
			changed.SourceRevision = strings.Repeat("a", 40)
		} else {
			changed.SourceDigest = strings.Repeat("b", 64)
		}
		if err := minimumCheckSource(t.Context(), root, changed); err == nil || err.Error() != "minimum smoke source snapshot changed during execution" {
			t.Fatalf("%s drift lost its source-identity error: %v", field, err)
		}
	}
}
