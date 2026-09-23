package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestOutputReplacementPreservesPermissionBoundary(t *testing.T) {
	for _, mode := range []os.FileMode{0o000, 0o200, 0o400, 0o600, 0o640, 0o644} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.WriteFile("report.json", []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod("report.json", mode); err != nil {
				t.Fatal(err)
			}
			if err := writeRepoRelativeOutputFile("report.json", []byte("new")); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat("report.json")
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("mode changed: info=%v error=%v", info, err)
			}
			if err := os.Chmod("report.json", mode|0o400); err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile("report.json")
			if err != nil || string(content) != "new" {
				t.Fatalf("content=%q error=%v", content, err)
			}
		})
	}
}

func TestOutputRejectsDestinationPermissionDrift(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("report.json", []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputWriterBarrier = func(stage, path string) {
		if stage == "before_rename" {
			if err := os.Chmod(path, 0o400); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() { outputWriterBarrier = nil })
	if err := writeRepoRelativeOutputFile("report.json", []byte("new")); err == nil {
		t.Fatal("destination mode mutation was overwritten")
	}
	content, err := os.ReadFile("report.json")
	if err != nil || string(content) != "old" {
		t.Fatalf("refused write changed content: %q %v", content, err)
	}
	info, err := os.Stat("report.json")
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("refused write changed destination permissions: %v %v", info, err)
	}
	entries, err := os.ReadDir(".")
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary output residue: %v %v", entries, err)
	}
}

func TestNewOutputDefaultIsExplicitUnderPrivateUmask(t *testing.T) {
	if os.Getenv("PROOFKIT_TEST_PRIVATE_UMASK") == "1" {
		if err := writeRepoRelativeOutputFile("new.json", []byte("new")); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat("new.json")
		if err != nil || info.Mode().Perm() != 0o644 {
			t.Fatalf("new output mode=%v error=%v", info, err)
		}
		return
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("POSIX umask witness requires sh")
	}
	command := exec.Command(shell, "-c", `umask 077; exec "$@"`, "output-mode-test", os.Args[0], "-test.run=^TestNewOutputDefaultIsExplicitUnderPrivateUmask$")
	command.Env = append(os.Environ(), "PROOFKIT_TEST_PRIVATE_UMASK=1")
	command.Dir = t.TempDir()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated umask witness: %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(command.Dir, "new.json")); err != nil {
		t.Fatal(err)
	}
}
