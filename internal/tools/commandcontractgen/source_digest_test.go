package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeSourceDigestPreservesFileSetAndFraming(t *testing.T) {
	root := t.TempDir()
	for path, content := range map[string]string{
		"pkg/a.go": "package a\n", "pkg/nested/b.go": "package b\n",
		"pkg/a_test.go": "not source", "pkg/b_generated.go": "not source", "pkg/readme.txt": "not source",
	} {
		absolute := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ path, framed string }{
		{"pkg/a.go", "pkg/a.go\x00package a\n\x00"},
		{"pkg", "pkg/a.go\x00package a\n\x00pkg/nested/b.go\x00package b\n\x00"},
	} {
		got, err := digestSourcePath(root, tc.path)
		want := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(tc.framed)))
		if err != nil || got != want {
			t.Fatalf("ordinary source digest changed: got=%s want=%s err=%v", got, want, err)
		}
	}
}

func TestNativeSourceDigestRejectsSymlinkTargetsAndComponents(t *testing.T) {
	for _, tc := range []struct {
		name, targetName, relative string
		external, directory        bool
	}{
		{"external file", "outside.txt", "pkg/alias.go", true, false},
		{"external walk", "outside.txt", "pkg", true, false},
		{"excluded test file", "owner_test.go", "pkg", false, false},
		{"excluded generated file", "owner_generated.go", "pkg", false, false},
		{"intermediate directory", "sources", "pkg/alias/native.go", true, true},
		{"descendant directory", "sources", "pkg", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "checkout")
			if err := os.MkdirAll(filepath.Join(root, "pkg"), 0700); err != nil {
				t.Fatal(err)
			}
			targetRoot := filepath.Join(root, "pkg")
			if tc.external {
				targetRoot = base
			}
			target := filepath.Join(targetRoot, tc.targetName)
			link := filepath.Join(root, "pkg", "alias.go")
			if tc.directory {
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(target, "native.go"), []byte("package target\n"), 0600); err != nil {
					t.Fatal(err)
				}
				link = filepath.Join(root, "pkg", "alias")
			} else if err := os.WriteFile(target, []byte("package target\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			if _, err := digestSourcePath(root, tc.relative); err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("symlink provenance admitted: %v", err)
			}
		})
	}
}
