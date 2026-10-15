package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const protectedOutputRefusal = "must not enter repository metadata or Proofkit control state"

// treeSnapshot records every entry's type, permission bits and content or link
// target, so equality proves byte and mode preservation and absent residue.
func treeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		record := info.Mode().String()
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			record += " -> " + target
		case info.Mode().IsRegular():
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(content)
			record += " " + hex.EncodeToString(sum[:])
		}
		snapshot[filepath.ToSlash(relative)] = record
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertSameTree(t *testing.T, label string, before, after map[string]string) {
	t.Helper()
	for path, record := range before {
		if after[path] != record {
			t.Errorf("%s changed %s: %q -> %q", label, path, record, after[path])
		}
	}
	for path, record := range after {
		if _, ok := before[path]; !ok {
			t.Errorf("%s created %s: %q", label, path, record)
		}
	}
}

func writeModeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func runSpecTreeViewOutput(t *testing.T, format, output string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	status := Run(t.Context(), []string{"requirement-spec-tree-view", "--input", "-", "--format", format, "--output", output}, strings.NewReader(cliRequirementSpecTreeInput()), &stdout, &stderr)
	return status, stdout.String(), stderr.String()
}

func TestPresentationOutputRefusesProtectedNamespacesPreservingBytesAndMode(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	writeModeFile(t, ".git/hooks/pre-commit", "#!/bin/sh\nexit 0\n", 0o755)
	writeModeFile(t, ".git/config", "[core]\n\tbare = false\n", 0o644)
	writeModeFile(t, "vendor/module/.git/hooks/post-merge", "#!/bin/sh\nexit 0\n", 0o755)
	writeModeFile(t, ".agentic-proofkit/transactions/journal.json", "{}\n", 0o600)
	lowerHook, err := os.Stat(".git/hooks/pre-commit")
	if err != nil {
		t.Fatal(err)
	}
	if upperHook, err := os.Stat(".GIT/hooks/pre-commit"); err == nil && os.SameFile(lowerHook, upperHook) {
		t.Log("host filesystem is case-insensitive: .GIT is a native alias of .git")
	}
	before := treeSnapshot(t, root)
	for _, output := range []string{
		".git/hooks/pre-commit",
		".git/hooks/post-checkout",
		".git",
		".GIT/hooks/pre-commit",
		".Git/config",
		".g\u200cit/hooks/pre-commit",
		"\ufeff.git/config",
		".gi\u202et/hooks/pre-commit",
		"vendor/module/.git/hooks/post-merge",
		"vendor/module/.GIT/hooks/post-merge",
		".agentic-proofkit/transactions/journal.json",
		".AGENTIC-PROOFKIT/transactions/journal.json",
		"docs/.agentic-proofkit/view.md",
	} {
		for _, format := range []string{"markdown", "json", "html"} {
			status, stdout, stderr := runSpecTreeViewOutput(t, format, output)
			if status != 1 || stdout != "" || !strings.Contains(stderr, protectedOutputRefusal) {
				t.Errorf("%s %q: status=%d stdout=%q stderr=%q", format, output, status, stdout, stderr)
			}
		}
		if err := writeRepoRelativeOutputFile(filepath.FromSlash(output), []byte("sink must refuse\n")); err == nil || !strings.Contains(err.Error(), protectedOutputRefusal) {
			t.Errorf("writer sink admitted %q: %v", output, err)
		}
	}
	assertSameTree(t, "protected refusal", before, treeSnapshot(t, root))
}

func TestPresentationOutputSymlinkAndHardLinkAliasesNeverReachHooks(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	writeModeFile(t, ".git/hooks/pre-commit", "#!/bin/sh\nexit 0\n", 0o755)
	if err := os.Mkdir("out", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".git/hooks", "hooks-link"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.git/hooks/pre-commit", filepath.Join("out", "hook.md")); err != nil {
		t.Fatal(err)
	}
	before := treeSnapshot(t, root)
	for output, refusal := range map[string]string{
		"hooks-link/pre-commit": "output parent must not contain a symlink",
		"out/hook.md":           "output path must not be a symlink",
	} {
		status, stdout, stderr := runSpecTreeViewOutput(t, "markdown", output)
		if status != 1 || stdout != "" || !strings.Contains(stderr, refusal) {
			t.Errorf("%q: status=%d stdout=%q stderr=%q", output, status, stdout, stderr)
		}
	}
	assertSameTree(t, "symlink alias refusal", before, treeSnapshot(t, root))

	// A hard link is an ordinary path. Rename replaces its directory entry and
	// never writes through the shared inode, so the hook keeps bytes and mode.
	if err := os.Link(filepath.Join(".git", "hooks", "pre-commit"), filepath.Join("out", "linked.md")); err != nil {
		t.Fatal(err)
	}
	hookBefore := treeSnapshot(t, filepath.Join(root, ".git"))
	status, stdout, stderr := runSpecTreeViewOutput(t, "markdown", "out/linked.md")
	if status != 0 || stdout != "" || stderr != "" {
		t.Fatalf("hard-linked ordinary output: status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	assertSameTree(t, "hard-link replacement", hookBefore, treeSnapshot(t, filepath.Join(root, ".git")))
	info, err := os.Stat(filepath.Join("out", "linked.md"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("replaced hard link mode=%v, want execute bits dropped to 0644", info.Mode().Perm())
	}
}

func TestPresentationOutputReplacementKeepsReadWriteBitsAndDropsExecuteBits(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	cases := map[string]struct {
		prior os.FileMode
		want  os.FileMode
	}{
		"out/new.md":               {want: 0o644},
		"out/private.md":           {prior: 0o600, want: 0o600},
		"out/shared.md":            {prior: 0o664, want: 0o664},
		"out/script.md":            {prior: 0o755, want: 0o644},
		"out/group-exec.md":        {prior: 0o750, want: 0o640},
		"out/exec-only.md":         {prior: 0o711, want: 0o600},
		".githooks/pre-commit":     {prior: 0o755, want: 0o644},
		".github/spec-tree.md":     {want: 0o644},
		".gitignore":               {prior: 0o644, want: 0o644},
		"docs/.git-notes/view.md":  {want: 0o644},
		"a.git/view.md":            {want: 0o644},
		".agentic-proofkit-view/x": {want: 0o644},
	}
	for output, mode := range cases {
		if mode.prior != 0 {
			writeModeFile(t, output, "prior\n", mode.prior)
		}
		status, stdout, stderr := runSpecTreeViewOutput(t, "markdown", output)
		if status != 0 || stdout != "" || stderr != "" {
			t.Fatalf("%q: status=%d stdout=%q stderr=%q", output, status, stdout, stderr)
		}
		info, err := os.Lstat(output)
		if err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != mode.want || !strings.Contains(string(content), "# Requirement Spec Tree View") {
			t.Errorf("%q: mode=%v want %v content=%q", output, info.Mode(), mode.want, content)
		}
	}
}

func TestPresentationOutputRefusesPathsOutsidePathIdentityDomain(t *testing.T) {
	t.Chdir(t.TempDir())
	// A component whose HFS+-visible form is "." or ".." passes the literal
	// repository-relative check but leaves the path-identity domain once the
	// ignorable code points are removed.
	for name, output := range map[string]string{
		"invalid UTF-8":    "out/\xff.md",
		"too many parts":   strings.Repeat("d/", 64) + "view.md",
		"too many bytes":   "out/" + strings.Repeat("v", 1021) + ".md",
		"visible dot":      "out/.\u200c/view.md",
		"visible parent":   "..\u200c/view.md",
		"admitted maximum": strings.Repeat("d/", 63) + "view.md",
	} {
		_, err := admitPresentationOutputPath(output)
		if name == "admitted maximum" {
			if err != nil {
				t.Errorf("%s refused: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "output path identity is invalid") {
			t.Errorf("%s admitted: %v", name, err)
		}
	}
}
