//go:build linux

package repositorytransaction

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDeletionRejectsDifferentFilesystemBeforeControlMutation(t *testing.T) {
	root := os.Getenv("PROOFKIT_CROSS_FILESYSTEM_ROOT")
	if root == "" {
		t.Skip("requires the isolated dual-filesystem fixture supplied by the source-quality CI step")
	}
	left, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	right, err := os.Stat(filepath.Join(root, "other"))
	if err != nil {
		t.Fatal(err)
	}
	same, err := platformSameFilesystem(left, right)
	if err != nil || same {
		t.Fatal("fixture must expose two distinct filesystems")
	}
	mustWriteTestFile(t, root, "other/owned", "before", 0o644)
	before := snapshotTestTree(t, root)
	_, err = BuildPlan(context.Background(), root, []Target{{Path: "other/owned", Absent: true}})
	if err == nil || !strings.Contains(err.Error(), "filesystem") || !reflect.DeepEqual(before, snapshotTestTree(t, root)) {
		t.Fatalf("cross-filesystem deletion was not rejected before effects: %v", err)
	}
}
