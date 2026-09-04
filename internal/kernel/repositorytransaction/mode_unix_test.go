//go:build darwin || linux

package repositorytransaction

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCreatedDirectoryModesDoNotDependOnUmask(t *testing.T) {
	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)

	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "nested/specs/state.json", Content: []byte("desired\n"), Mode: 0o644}})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Apply(context.Background(), root, plan); err != nil || result.State != StateApplied {
		t.Fatalf("Apply() result=%#v error=%v", result, err)
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{path: "nested", mode: 0o755},
		{path: "nested/specs", mode: 0o755},
		{path: ControlRoot, mode: 0o700},
		{path: ControlDirectory, mode: 0o700},
	} {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(item.path)))
		if err != nil || info.Mode().Perm() != item.mode {
			t.Fatalf("%s mode=%v error=%v, want %04o", item.path, infoMode(info), err, item.mode)
		}
	}
}
