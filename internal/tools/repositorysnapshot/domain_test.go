package repositorysnapshot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterializePreservesItsDomainBeyondTheExactRouteBudget(t *testing.T) {
	root := initializeRepository(t)
	writeFile(t, filepath.Join(root, ".gitignore"), "wide/*\n!wide/f00000\n")
	for index := range 16_384 {
		writeFile(t, filepath.Join(root, "wide", fmt.Sprintf("f%05d", index)), "x")
	}
	runGit(t, root, "add", ".gitignore", "wide/f00000")
	runGit(t, root, "commit", "-qm", "fixture")
	for _, count := range []int{16_384, 16_385} {
		if count == 16_385 {
			writeFile(t, filepath.Join(root, "wide", "f16384"), "x")
		}
		destination := t.TempDir()
		snapshot, err := Materialize(root, destination)
		if err != nil || len(snapshot.Paths) != 2 {
			t.Fatalf("%d siblings with two admitted files: %v", count, err)
		}
		if content, err := os.ReadFile(filepath.Join(destination, "wide", "f00000")); err != nil || string(content) != "x" {
			t.Fatalf("materialized bytes = %q, %v", content, err)
		}
		if err := ValidateMaterialized(destination, snapshot); err != nil {
			t.Fatal(err)
		}
	}
	// The admitted maximum includes .gitignore and 19999 ordinary source files.
	writeFile(t, filepath.Join(root, ".gitignore"), "")
	for index := 16_385; index < 19_999; index++ {
		writeFile(t, filepath.Join(root, "wide", fmt.Sprintf("f%05d", index)), "x")
	}
	destination := t.TempDir()
	snapshot, err := Materialize(root, destination)
	if err != nil || len(snapshot.Paths) != 20_000 {
		t.Fatalf("the existing 20000-file domain must remain admitted: paths=%d err=%v", len(snapshot.Paths), err)
	}
	if err := ValidateMaterialized(destination, snapshot); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "wide", "f19999"), "x")
	if _, err := Materialize(root, t.TempDir()); err == nil || !strings.Contains(err.Error(), "file-count limit") {
		t.Fatalf("the existing upper bound must remain enforced: %v", err)
	}
}
